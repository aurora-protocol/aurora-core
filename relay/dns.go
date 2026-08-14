package relay

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/aurora-protocol/aurora-core/protocol"
)

const (
	socketDNSHeaderBytes    = 12
	maximumSocketDNSBytes   = 4096
	maximumSocketDNSAnswers = 32
	maximumSocketDNSExtra   = 4
	maximumSocketDNSRecords = 384
	socketDNSResolveTimeout = 5 * time.Second

	socketDNSFlagResponse           = 0x8000
	socketDNSFlagOpcodeMask         = 0x7800
	socketDNSFlagRecursionDesired   = 0x0100
	socketDNSFlagRecursionAvailable = 0x0080

	socketDNSClassIN   = 1
	socketDNSTypeA     = 1
	socketDNSTypeAAAA  = 28
	socketDNSTypeSVCB  = 64
	socketDNSTypeHTTPS = 65
	socketDNSSvcIPv4   = 4
	socketDNSSvcIPv6   = 6
	socketDNSRCodeOK   = 0
	socketDNSRCodeForm = 1
	socketDNSRCodeFail = 2
	socketDNSRCodeNo   = 4
	socketDNSRCodeDeny = 5
)

type socketDNSQuestion struct {
	transactionID uint16
	recursion     bool
	domain        string
	queryType     uint16
	wire          []byte
}

func (e *SocketEgress) handleDNSMessage(ctx context.Context, event ExitFrameEvent) ([]protocol.AuroraFrame, error) {
	question, err := parseSocketDNSQuestion(event.Data)
	if err != nil {
		return nil, ErrExitEventInvalid
	}
	responseCode := uint16(socketDNSRCodeOK)
	var answers []netip.Addr
	switch {
	case !e.policy.AllowDomain(question.domain):
		responseCode = socketDNSRCodeDeny
	case question.queryType != socketDNSTypeA && question.queryType != socketDNSTypeAAAA:
		if isNilExitDependency(e.dnsResolver) {
			responseCode = socketDNSRCodeFail
			break
		}
		timeout := socketDNSResolveTimeout
		if e.limits.DialTimeout < timeout {
			timeout = e.limits.DialTimeout
		}
		opCtx, stop := e.operationContext(ctx, timeout)
		message, resolveErr := e.dnsResolver.ExchangeDNS(opCtx, append([]byte(nil), event.Data...))
		stop()
		if resolveErr != nil || validateSocketDNSResponse(question, message, e.policy) != nil {
			if lifecycleErr := e.lifecycleError(ctx); lifecycleErr != nil {
				return nil, lifecycleErr
			}
			responseCode = socketDNSRCodeFail
			break
		}
		frame, frameErr := protocol.NewDNSMessageFrame(event.FlowID, message)
		if frameErr != nil {
			return nil, frameErr
		}
		return []protocol.AuroraFrame{frame}, nil
	default:
		network := "ip4"
		if question.queryType == socketDNSTypeAAAA {
			network = "ip6"
		}
		timeout := socketDNSResolveTimeout
		if e.limits.DialTimeout < timeout {
			timeout = e.limits.DialTimeout
		}
		opCtx, stop := e.operationContext(ctx, timeout)
		resolved, resolveErr := e.resolver.LookupNetIP(opCtx, network, question.domain)
		stop()
		if resolveErr != nil {
			if lifecycleErr := e.lifecycleError(ctx); lifecycleErr != nil {
				return nil, lifecycleErr
			}
			responseCode = socketDNSRCodeFail
		} else {
			answers, responseCode = e.filterDNSAnswers(question.queryType, resolved)
		}
	}
	message := buildSocketDNSResponse(question, responseCode, answers, e.limits.ResolvedTTLSeconds)
	frame, err := protocol.NewDNSMessageFrame(event.FlowID, message)
	if err != nil {
		return nil, err
	}
	return []protocol.AuroraFrame{frame}, nil
}

func (e *SocketEgress) filterDNSAnswers(queryType uint16, resolved []netip.Addr) ([]netip.Addr, uint16) {
	if len(resolved) > maximumSocketDNSAnswers {
		return nil, socketDNSRCodeFail
	}
	answers := make([]netip.Addr, 0, len(resolved))
	seen := make(map[netip.Addr]struct{}, len(resolved))
	for _, answer := range resolved {
		answer = answer.Unmap()
		if (queryType == socketDNSTypeA && !answer.Is4()) || (queryType == socketDNSTypeAAAA && !answer.Is6()) {
			continue
		}
		if !e.policy.AllowIP(answer.String()) {
			return nil, socketDNSRCodeFail
		}
		if _, ok := seen[answer]; ok {
			continue
		}
		seen[answer] = struct{}{}
		answers = append(answers, answer)
	}
	sort.Slice(answers, func(i, j int) bool { return answers[i].Less(answers[j]) })
	return answers, socketDNSRCodeOK
}

func parseSocketDNSQuestion(message []byte) (socketDNSQuestion, error) {
	if len(message) < socketDNSHeaderBytes || len(message) > maximumSocketDNSBytes {
		return socketDNSQuestion{}, ErrExitEventInvalid
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&socketDNSFlagResponse != 0 || flags&socketDNSFlagOpcodeMask != 0 || binary.BigEndian.Uint16(message[4:6]) != 1 || binary.BigEndian.Uint16(message[6:8]) != 0 || binary.BigEndian.Uint16(message[8:10]) != 0 || binary.BigEndian.Uint16(message[10:12]) > maximumSocketDNSExtra {
		return socketDNSQuestion{}, ErrExitEventInvalid
	}
	offset := socketDNSHeaderBytes
	labels := make([]string, 0, 4)
	nameBytes := 0
	for {
		if offset >= len(message) {
			return socketDNSQuestion{}, ErrExitEventInvalid
		}
		labelLength := int(message[offset])
		offset++
		nameBytes++
		if labelLength == 0 {
			break
		}
		if labelLength > 63 || nameBytes+labelLength > 255 || offset+labelLength > len(message) {
			return socketDNSQuestion{}, ErrExitEventInvalid
		}
		label := message[offset : offset+labelLength]
		for _, value := range label {
			if value < 0x21 || value > 0x7e || value == '.' {
				return socketDNSQuestion{}, ErrExitEventInvalid
			}
		}
		labels = append(labels, strings.ToLower(string(label)))
		offset += labelLength
		nameBytes += labelLength
	}
	if len(labels) == 0 || offset+4 > len(message) {
		return socketDNSQuestion{}, ErrExitEventInvalid
	}
	queryType := binary.BigEndian.Uint16(message[offset : offset+2])
	if binary.BigEndian.Uint16(message[offset+2:offset+4]) != socketDNSClassIN {
		return socketDNSQuestion{}, ErrExitEventInvalid
	}
	offset += 4
	for additional := 0; additional < int(binary.BigEndian.Uint16(message[10:12])); additional++ {
		if err := skipSocketDNSRecord(message, &offset); err != nil {
			return socketDNSQuestion{}, ErrExitEventInvalid
		}
	}
	if offset != len(message) {
		return socketDNSQuestion{}, ErrExitEventInvalid
	}
	return socketDNSQuestion{
		transactionID: binary.BigEndian.Uint16(message[:2]),
		recursion:     flags&socketDNSFlagRecursionDesired != 0,
		domain:        strings.Join(labels, "."),
		queryType:     queryType,
		wire:          append([]byte(nil), message[socketDNSHeaderBytes:offset]...),
	}, nil
}

func skipSocketDNSRecord(message []byte, offset *int) error {
	nameBytes := 0
	for {
		if *offset >= len(message) {
			return ErrExitEventInvalid
		}
		labelLength := int(message[*offset])
		*offset++
		nameBytes++
		if labelLength == 0 {
			break
		}
		if labelLength > 63 || nameBytes+labelLength > 255 || *offset+labelLength > len(message) {
			return ErrExitEventInvalid
		}
		for _, value := range message[*offset : *offset+labelLength] {
			if value < 0x21 || value > 0x7e || value == '.' {
				return ErrExitEventInvalid
			}
		}
		*offset += labelLength
		nameBytes += labelLength
	}
	if *offset+10 > len(message) {
		return ErrExitEventInvalid
	}
	rdataLength := int(binary.BigEndian.Uint16(message[*offset+8 : *offset+10]))
	*offset += 10
	if rdataLength > len(message)-*offset {
		return ErrExitEventInvalid
	}
	*offset += rdataLength
	return nil
}

func validateSocketDNSResponse(question socketDNSQuestion, message []byte, policy ExitPolicy) error {
	if len(message) < socketDNSHeaderBytes || len(message) > maximumSocketDNSBytes {
		return ErrExitEventInvalid
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if binary.BigEndian.Uint16(message[:2]) != question.transactionID || flags&socketDNSFlagResponse == 0 || flags&socketDNSFlagOpcodeMask != 0 || binary.BigEndian.Uint16(message[4:6]) != 1 {
		return ErrExitEventInvalid
	}
	offset := socketDNSHeaderBytes
	if err := skipSocketDNSCompressedName(message, &offset); err != nil || offset+4 > len(message) || !bytes.Equal(message[socketDNSHeaderBytes:offset+4], question.wire) {
		return ErrExitEventInvalid
	}
	offset += 4
	recordCount := int(binary.BigEndian.Uint16(message[6:8])) + int(binary.BigEndian.Uint16(message[8:10])) + int(binary.BigEndian.Uint16(message[10:12]))
	if recordCount > maximumSocketDNSRecords {
		return ErrExitEventInvalid
	}
	for record := 0; record < recordCount; record++ {
		if err := validateSocketDNSResponseRecord(message, &offset, policy); err != nil {
			return ErrExitEventInvalid
		}
	}
	if offset != len(message) {
		return ErrExitEventInvalid
	}
	return nil
}

func validateSocketDNSResponseRecord(message []byte, offset *int, policy ExitPolicy) error {
	if err := skipSocketDNSCompressedName(message, offset); err != nil || *offset+10 > len(message) {
		return ErrExitEventInvalid
	}
	recordType := binary.BigEndian.Uint16(message[*offset : *offset+2])
	recordClass := binary.BigEndian.Uint16(message[*offset+2 : *offset+4])
	rdataLength := int(binary.BigEndian.Uint16(message[*offset+8 : *offset+10]))
	*offset += 10
	if rdataLength > len(message)-*offset {
		return ErrExitEventInvalid
	}
	rdata := message[*offset : *offset+rdataLength]
	*offset += rdataLength
	if recordClass != socketDNSClassIN {
		return nil
	}
	switch recordType {
	case socketDNSTypeA:
		if len(rdata) != 4 || !policy.AllowIP(netip.AddrFrom4([4]byte(rdata)).String()) {
			return ErrExitPolicyDenied
		}
	case socketDNSTypeAAAA:
		if len(rdata) != 16 || !policy.AllowIP(netip.AddrFrom16([16]byte(rdata)).String()) {
			return ErrExitPolicyDenied
		}
	case socketDNSTypeSVCB, socketDNSTypeHTTPS:
		if err := validateSocketDNSServiceBindingHints(message, rdata, policy); err != nil {
			return err
		}
	}
	return nil
}

func skipSocketDNSCompressedName(message []byte, offset *int) error {
	nameBytes := 0
	for labels := 0; labels <= 127; labels++ {
		if *offset >= len(message) {
			return ErrExitEventInvalid
		}
		labelLength := int(message[*offset])
		if labelLength&0xc0 == 0xc0 {
			if *offset+2 > len(message) || int(binary.BigEndian.Uint16(message[*offset:*offset+2])&0x3fff) >= *offset {
				return ErrExitEventInvalid
			}
			*offset += 2
			return nil
		}
		if labelLength&0xc0 != 0 {
			return ErrExitEventInvalid
		}
		*offset++
		nameBytes++
		if labelLength == 0 {
			return nil
		}
		if labelLength > 63 || nameBytes+labelLength > 255 || *offset+labelLength > len(message) {
			return ErrExitEventInvalid
		}
		*offset += labelLength
		nameBytes += labelLength
	}
	return ErrExitEventInvalid
}

func validateSocketDNSServiceBindingHints(message, rdata []byte, policy ExitPolicy) error {
	if len(rdata) < 3 {
		return ErrExitEventInvalid
	}
	offset := 2
	base := len(message) - len(rdata)
	nameOffset := base + offset
	if err := skipSocketDNSCompressedName(message, &nameOffset); err != nil || nameOffset < base || nameOffset > len(message) {
		return ErrExitEventInvalid
	}
	offset = nameOffset - base
	for offset < len(rdata) {
		if len(rdata)-offset < 4 {
			return ErrExitEventInvalid
		}
		parameter := binary.BigEndian.Uint16(rdata[offset : offset+2])
		length := int(binary.BigEndian.Uint16(rdata[offset+2 : offset+4]))
		offset += 4
		if length > len(rdata)-offset {
			return ErrExitEventInvalid
		}
		value := rdata[offset : offset+length]
		offset += length
		switch parameter {
		case socketDNSSvcIPv4:
			if len(value)%4 != 0 {
				return ErrExitEventInvalid
			}
			for len(value) != 0 {
				if !policy.AllowIP(netip.AddrFrom4([4]byte(value[:4])).String()) {
					return ErrExitPolicyDenied
				}
				value = value[4:]
			}
		case socketDNSSvcIPv6:
			if len(value)%16 != 0 {
				return ErrExitEventInvalid
			}
			for len(value) != 0 {
				if !policy.AllowIP(netip.AddrFrom16([16]byte(value[:16])).String()) {
					return ErrExitPolicyDenied
				}
				value = value[16:]
			}
		}
	}
	return nil
}

func buildSocketDNSResponse(question socketDNSQuestion, responseCode uint16, answers []netip.Addr, ttl uint32) []byte {
	answerBytes := 0
	for _, answer := range answers {
		if answer.Is4() {
			answerBytes += 16
		} else {
			answerBytes += 28
		}
	}
	response := make([]byte, socketDNSHeaderBytes, socketDNSHeaderBytes+len(question.wire)+answerBytes)
	binary.BigEndian.PutUint16(response[:2], question.transactionID)
	flags := uint16(socketDNSFlagResponse | socketDNSFlagRecursionAvailable)
	if question.recursion {
		flags |= socketDNSFlagRecursionDesired
	}
	binary.BigEndian.PutUint16(response[2:4], flags|responseCode)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(answers)))
	response = append(response, question.wire...)
	for _, answer := range answers {
		response = append(response, 0xc0, 0x0c)
		if answer.Is4() {
			response = binary.BigEndian.AppendUint16(response, socketDNSTypeA)
		} else {
			response = binary.BigEndian.AppendUint16(response, socketDNSTypeAAAA)
		}
		response = binary.BigEndian.AppendUint16(response, socketDNSClassIN)
		response = binary.BigEndian.AppendUint32(response, ttl)
		if answer.Is4() {
			response = binary.BigEndian.AppendUint16(response, 4)
			address := answer.As4()
			response = append(response, address[:]...)
		} else {
			response = binary.BigEndian.AppendUint16(response, 16)
			address := answer.As16()
			response = append(response, address[:]...)
		}
	}
	return response
}
