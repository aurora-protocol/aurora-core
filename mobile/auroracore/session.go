package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/aurora-protocol/aurora-core/admission"
	"github.com/aurora-protocol/aurora-core/client"
	"github.com/aurora-protocol/aurora-core/handshake"
	"github.com/aurora-protocol/aurora-core/issuerd"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/server"
	"github.com/aurora-protocol/aurora-core/session"
	"github.com/aurora-protocol/aurora-core/transport"
	"github.com/aurora-protocol/aurora-core/wire"
)

const (
	maximumNativeSessions          = 64
	maximumNativeIssuerResponse    = 1 << 20
	maximumNativeSessionPacket     = 1 << 24
	maximumNativeIssuerWorkBytes   = 8 << 10
	maximumNativeLocalPacketBytes  = 65535
	maximumNativeLocalPacketResult = 1 << 20
	maximumNativeLocalPacketQueue  = 64
	nativeSessionHandshakeTimeout  = 30 * time.Second
	nativeSessionIssuerTimeout     = 2 * time.Minute
	nativeSessionCompletionTimeout = 30 * time.Second
	nativeIssuerLifetime           = 5 * time.Minute
)

type nativeSessionHandshake interface {
	Complete(context.Context, protocol.AdmissionProof, protocol.ReplayProof) (*handshake.EstablishedSession, error)
	Close() error
}

type nativeSessionStarter func(context.Context, client.NativeProvisioning, time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error)

type nativeSessionRegistryOptions struct {
	now           func() time.Time
	random        io.Reader
	start         nativeSessionStarter
	issuerTimeout time.Duration
}

type nativeSessionRegistry struct {
	mu            sync.Mutex
	randomMu      sync.Mutex
	next          uint64
	sessions      map[uint64]*nativeSession
	now           func() time.Time
	random        io.Reader
	start         nativeSessionStarter
	issuerTimeout time.Duration
}

type nativeSession struct {
	mu             sync.Mutex
	localIngressMu sync.Mutex

	context           context.Context
	cancel            context.CancelFunc
	handshake         nativeSessionHandshake
	established       *handshake.EstablishedSession
	adapter           *client.PacketAdapter
	localPackets      chan []byte
	issuerURL         string
	issuerCarrierPath string
	request           handshake.ClientProofRequest
	issuerTimer       *time.Timer
	duplexActive      bool
	pumpErr           error
	completing        bool
	closed            bool
}

type nativeIssuerWork struct {
	Handle            uint64
	IssuerURL         string
	IssuerCarrierPath string
	RequestBody       []byte
}

var nativeSessions = newNativeSessionRegistry(nativeSessionRegistryOptions{})

func newNativeSessionRegistry(options nativeSessionRegistryOptions) *nativeSessionRegistry {
	if options.now == nil {
		options.now = time.Now
	}
	if options.random == nil {
		options.random = rand.Reader
	}
	if options.start == nil {
		options.start = startNativeSession
	}
	if options.issuerTimeout <= 0 {
		options.issuerTimeout = nativeSessionIssuerTimeout
	}
	return &nativeSessionRegistry{
		next:          1,
		sessions:      make(map[uint64]*nativeSession),
		now:           options.now,
		random:        options.random,
		start:         options.start,
		issuerTimeout: options.issuerTimeout,
	}
}

func (r *nativeSessionRegistry) begin(provisioning client.NativeProvisioning) (nativeIssuerWork, error) {
	if r == nil {
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native session registry is unavailable")
	}
	defer zeroNativeProvisioning(&provisioning)
	now := r.now().UTC()
	if now.IsZero() || now.Unix() < 0 {
		return nativeIssuerWork{}, fmt.Errorf("auroracore: invalid native session time")
	}
	sessionContext, cancel := context.WithCancel(context.Background())
	timeout := time.AfterFunc(nativeSessionHandshakeTimeout, cancel)
	deferred, request, err := r.start(sessionContext, provisioning, now)
	if !timeout.Stop() {
		cancel()
		if deferred != nil {
			_ = deferred.Close()
		}
		zeroNativeProofRequest(&request)
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native session handshake timed out")
	}
	if err != nil {
		cancel()
		zeroNativeProofRequest(&request)
		return nativeIssuerWork{}, err
	}
	if deferred == nil {
		cancel()
		zeroNativeProofRequest(&request)
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native session starter returned no handshake")
	}
	request = cloneNativeProofRequest(request)
	work, err := r.issueWork(provisioning.IssuerURL, provisioning.IssuerCarrierPath, request, now)
	if err != nil {
		cancel()
		_ = deferred.Close()
		zeroNativeProofRequest(&request)
		return nativeIssuerWork{}, err
	}
	session := &nativeSession{
		context:           sessionContext,
		cancel:            cancel,
		handshake:         deferred,
		localPackets:      make(chan []byte, maximumNativeLocalPacketQueue),
		issuerURL:         provisioning.IssuerURL,
		issuerCarrierPath: provisioning.IssuerCarrierPath,
		request:           request,
	}
	r.mu.Lock()
	if len(r.sessions) >= maximumNativeSessions {
		r.mu.Unlock()
		_ = session.close()
		zeroNativeIssuerWork(&work)
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native session limit reached")
	}
	handle, err := r.allocateHandleLocked()
	if err == nil {
		r.sessions[handle] = session
		session.mu.Lock()
		session.issuerTimer = time.AfterFunc(r.issuerTimeout, func() {
			r.expire(handle, session)
		})
		session.mu.Unlock()
	}
	r.mu.Unlock()
	if err != nil {
		_ = session.close()
		zeroNativeIssuerWork(&work)
		return nativeIssuerWork{}, err
	}
	work.Handle = handle
	return work, nil
}

func (r *nativeSessionRegistry) issueWork(issuerURL, issuerCarrierPath string, request handshake.ClientProofRequest, now time.Time) (nativeIssuerWork, error) {
	if issuerURL == "" || issuerCarrierPath == "" || len(request.AdmissionContextHash) != 48 || request.ReplayEpochValidUntil == 0 {
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native issuer work inputs are invalid")
	}
	nowUnix := uint64(now.Unix())
	if request.ReplayEpochValidUntil <= nowUnix+1 {
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native replay epoch expires too soon")
	}
	expiry := uint64(now.Add(nativeIssuerLifetime).Unix())
	if expiry >= request.ReplayEpochValidUntil {
		expiry = request.ReplayEpochValidUntil - 1
	}
	if expiry <= nowUnix {
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native issuer proof would be expired")
	}
	tokenNonce := make([]byte, 32)
	defer zeroNativeBytes(tokenNonce)
	if err := r.readRandom(tokenNonce); err != nil {
		return nativeIssuerWork{}, fmt.Errorf("auroracore: generate issuer token nonce: %w", err)
	}
	payload, err := server.EncodeCarrierIssueRequest(tokenNonce, request.AdmissionContextHash, expiry)
	if err != nil {
		return nativeIssuerWork{}, fmt.Errorf("auroracore: encode issuer request: %w", err)
	}
	defer zeroNativeBytes(payload)
	body := server.EncodeCarrier(server.CarrierBlindRSAIssueReq, payload)
	if len(body) > maximumNativeIssuerWorkBytes {
		zeroNativeBytes(body)
		return nativeIssuerWork{}, fmt.Errorf("auroracore: native issuer request exceeds size limit")
	}
	return nativeIssuerWork{
		IssuerURL:         issuerURL,
		IssuerCarrierPath: issuerCarrierPath,
		RequestBody:       body,
	}, nil
}

func (r *nativeSessionRegistry) complete(handle uint64, issuerResponse []byte) error {
	if len(issuerResponse) == 0 || len(issuerResponse) > maximumNativeIssuerResponse {
		return fmt.Errorf("auroracore: native issuer response size is invalid")
	}
	session, err := r.lookup(handle)
	if err != nil {
		return err
	}
	session.mu.Lock()
	if session.closed || session.completing || session.handshake == nil || session.established != nil {
		session.mu.Unlock()
		return fmt.Errorf("auroracore: native session is not awaiting issuer completion")
	}
	session.completing = true
	request := cloneNativeProofRequest(session.request)
	deferred := session.handshake
	session.mu.Unlock()

	proof, replay, err := r.proofsForIssuerResponse(request, issuerResponse)
	zeroNativeProofRequest(&request)
	var established *handshake.EstablishedSession
	var adapter *client.PacketAdapter
	if err == nil {
		session.mu.Lock()
		sessionContext := session.context
		session.mu.Unlock()
		if sessionContext == nil {
			err = fmt.Errorf("auroracore: native session context is unavailable")
		} else if sessionContext.Err() != nil {
			err = sessionContext.Err()
		} else {
			completionContext, cancel := context.WithTimeout(sessionContext, nativeSessionCompletionTimeout)
			established, err = deferred.Complete(completionContext, proof, replay)
			cancel()
		}
		if err == nil && (established == nil || established.Application == nil) {
			if established != nil {
				_ = established.Close()
			}
			established = nil
			err = fmt.Errorf("auroracore: native handshake completed without application session")
		}
		if err == nil {
			adapter, err = client.NewPacketAdapter(established.Application, client.PacketAdapterOptions{})
			if err != nil {
				err = fmt.Errorf("auroracore: create native packet adapter: %w", err)
			}
		}
	}
	zeroNativeAdmissionProof(&proof)
	zeroNativeReplayProof(&replay)

	startDuplex := false
	session.mu.Lock()
	session.completing = false
	if session.closed {
		session.mu.Unlock()
		if established != nil {
			_ = established.Close()
		}
		return fmt.Errorf("auroracore: native session is closed")
	}
	if err == nil {
		if (established.ReadCarrier == nil) != (established.WriteCarrier == nil) {
			err = fmt.Errorf("auroracore: native handshake returned incomplete carrier streams")
		} else {
			session.established = established
			session.adapter = adapter
			session.handshake = nil
			session.duplexActive = established.ReadCarrier != nil
			startDuplex = session.duplexActive
			zeroNativeProofRequest(&session.request)
			if session.issuerTimer != nil {
				session.issuerTimer.Stop()
				session.issuerTimer = nil
			}
		}
	}
	session.mu.Unlock()
	if err != nil {
		if established != nil {
			_ = established.Close()
		}
		_ = r.close(handle)
		return fmt.Errorf("auroracore: complete native session: %w", err)
	}
	if startDuplex {
		go r.runNativeDuplex(handle, session)
	}
	return nil
}

func (r *nativeSessionRegistry) proofsForIssuerResponse(request handshake.ClientProofRequest, issuerResponse []byte) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	carrierType, payload, err := server.DecodeCarrier(issuerResponse)
	if err != nil || carrierType != server.CarrierBlindRSAIssueResp || len(payload) == 0 {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("auroracore: invalid native issuer response")
	}
	proof, err := issuerd.DecodeAdmissionProofBytes(payload)
	if err != nil {
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("auroracore: decode admission proof: %w", err)
	}
	redemption, err := admission.TokenRedemptionHash(proof)
	if err != nil {
		zeroNativeAdmissionProof(&proof)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("auroracore: hash admission proof: %w", err)
	}
	defer zeroNativeBytes(redemption)
	replay := protocol.ReplayProof{
		ProofVersion:        proof.ProofVersion,
		ReplayEpochID:       request.ReplayEpochID,
		TokenRedemptionHash: append([]byte(nil), redemption...),
		ClientReplayNonce:   make([]byte, 32),
		ReplayWindowID:      append([]byte(nil), request.ReplayWindowID...),
	}
	if err := r.readRandom(replay.ClientReplayNonce); err != nil {
		zeroNativeAdmissionProof(&proof)
		zeroNativeReplayProof(&replay)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("auroracore: generate replay nonce: %w", err)
	}
	replay.ReplayContextHash, err = admission.ReplayContextHash(redemption, replay, request.RouteInstanceID, request.HopIndex, request.HandshakeBindingContext, request.AdmissionContextHash)
	if err != nil {
		zeroNativeAdmissionProof(&proof)
		zeroNativeReplayProof(&replay)
		return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("auroracore: bind replay proof: %w", err)
	}
	return proof, replay, nil
}

func (r *nativeSessionRegistry) close(handle uint64) error {
	if r == nil || handle == 0 {
		return fmt.Errorf("auroracore: native session handle is invalid")
	}
	r.mu.Lock()
	session, ok := r.sessions[handle]
	if ok {
		delete(r.sessions, handle)
	}
	r.mu.Unlock()
	if !ok {
		return fmt.Errorf("auroracore: native session handle is unknown")
	}
	return session.close()
}

func (r *nativeSessionRegistry) expire(handle uint64, want *nativeSession) {
	if r == nil || handle == 0 || want == nil {
		return
	}
	r.mu.Lock()
	if r.sessions[handle] != want {
		r.mu.Unlock()
		return
	}
	delete(r.sessions, handle)
	r.mu.Unlock()
	_ = want.close()
}

func (r *nativeSessionRegistry) queueFrameBlock(handle uint64, encoded []byte) error {
	if len(encoded) == 0 || len(encoded) > maximumNativeSessionPacket {
		return fmt.Errorf("auroracore: native frame block size is invalid")
	}
	block, err := protocol.DecodeFrameBlock(encoded)
	if err != nil {
		return fmt.Errorf("auroracore: decode native frame block: %w", err)
	}
	defer zeroNativeFrameBlock(&block)
	session, err := r.lookup(handle)
	if err != nil {
		return err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.established == nil || session.established.Application == nil {
		return fmt.Errorf("auroracore: native session is not established")
	}
	if session.duplexActive {
		return fmt.Errorf("auroracore: carrier-backed native session owns frame transport")
	}
	return session.established.Application.QueueFrames(context.Background(), block)
}

func (r *nativeSessionRegistry) nextPacket(handle uint64) ([]byte, error) {
	session, err := r.lookup(handle)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.established == nil || session.established.Application == nil {
		return nil, fmt.Errorf("auroracore: native session is not established")
	}
	if session.duplexActive {
		return nil, fmt.Errorf("auroracore: carrier-backed native session owns encrypted packets")
	}
	return session.established.Application.TryNextPacket()
}

func (r *nativeSessionRegistry) handlePacket(handle uint64, encoded []byte) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > maximumNativeSessionPacket {
		return nil, fmt.Errorf("auroracore: native encrypted packet size is invalid")
	}
	session, err := r.lookup(handle)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	defer session.mu.Unlock()
	if session.closed || session.established == nil || session.established.Application == nil {
		return nil, fmt.Errorf("auroracore: native session is not established")
	}
	if session.duplexActive {
		return nil, fmt.Errorf("auroracore: carrier-backed native session owns encrypted packets")
	}
	blocks, err := session.established.Application.HandlePacket(context.Background(), r.now(), encoded)
	if err != nil {
		return nil, err
	}
	defer zeroNativeFrameBlocks(blocks)
	return encodeNativeFrameBlocks(blocks)
}

func (r *nativeSessionRegistry) ingressLocalPacket(handle uint64, encoded []byte) ([][]byte, error) {
	if len(encoded) == 0 || len(encoded) > maximumNativeLocalPacketBytes {
		return nil, fmt.Errorf("auroracore: native local packet size is invalid")
	}
	session, err := r.lookup(handle)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	if session.closed || session.established == nil || session.adapter == nil || session.context == nil {
		session.mu.Unlock()
		return nil, fmt.Errorf("auroracore: native session packet adapter is unavailable")
	}
	packetContext := session.context
	adapter := session.adapter
	session.mu.Unlock()
	if err := packetContext.Err(); err != nil {
		return nil, err
	}
	session.localIngressMu.Lock()
	defer session.localIngressMu.Unlock()
	if err := adapter.Ingress(packetContext, encoded, r.now()); err != nil {
		return nil, err
	}
	return adapter.DrainLocalPackets(), nil
}

func (r *nativeSessionRegistry) nextLocalPacket(ctx context.Context, handle uint64) ([]byte, error) {
	if ctx == nil {
		return nil, fmt.Errorf("auroracore: native local packet context is nil")
	}
	session, err := r.lookup(handle)
	if err != nil {
		return nil, err
	}
	session.mu.Lock()
	if session.closed || session.established == nil || session.adapter == nil || session.context == nil || session.localPackets == nil {
		session.mu.Unlock()
		return nil, fmt.Errorf("auroracore: native session packet adapter is unavailable")
	}
	packetContext := session.context
	packets := session.localPackets
	session.mu.Unlock()
	for {
		select {
		case packet := <-packets:
			if len(packet) == 0 {
				return nil, fmt.Errorf("auroracore: native local packet is invalid")
			}
			return packet, nil
		default:
		}
		select {
		case packet := <-packets:
			if len(packet) == 0 {
				return nil, fmt.Errorf("auroracore: native local packet is invalid")
			}
			return packet, nil
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-packetContext.Done():
			select {
			case packet := <-packets:
				if len(packet) == 0 {
					return nil, fmt.Errorf("auroracore: native local packet is invalid")
				}
				return packet, nil
			default:
				return nil, session.localPacketTerminationError()
			}
		}
	}
}

func (r *nativeSessionRegistry) runNativeDuplex(handle uint64, session *nativeSession) {
	if r == nil || session == nil {
		return
	}
	session.mu.Lock()
	packetContext := session.context
	established := session.established
	adapter := session.adapter
	session.mu.Unlock()
	if packetContext == nil || established == nil || adapter == nil {
		r.finishNativeDuplex(handle, session, fmt.Errorf("auroracore: native duplex is unavailable"))
		return
	}
	err := transport.RunPacketDuplex(packetContext, established.ReadCarrier, established.WriteCarrier, established.Application, func(frameContext context.Context, block protocol.FrameBlock) error {
		packets, err := adapter.HandleFrameBlocks(frameContext, []protocol.FrameBlock{block}, r.now())
		if err != nil {
			return err
		}
		defer zeroNativeLocalPackets(packets)
		for _, packet := range packets {
			if err := session.enqueueLocalPacket(frameContext, packet); err != nil {
				return err
			}
		}
		return nil
	}, transport.DefaultMaxRecordBodyBytes)
	r.finishNativeDuplex(handle, session, err)
}

func (r *nativeSessionRegistry) finishNativeDuplex(handle uint64, session *nativeSession, err error) {
	if r == nil || handle == 0 || session == nil {
		return
	}
	session.finishDuplex(err)
	r.mu.Lock()
	if r.sessions[handle] == session {
		delete(r.sessions, handle)
	}
	r.mu.Unlock()
	_ = session.close()
}

func (s *nativeSession) enqueueLocalPacket(ctx context.Context, packet []byte) error {
	if s == nil || ctx == nil || len(packet) == 0 || len(packet) > maximumNativeLocalPacketBytes {
		return fmt.Errorf("auroracore: native local packet is invalid")
	}
	s.mu.Lock()
	packetContext := s.context
	packets := s.localPackets
	closed := s.closed
	s.mu.Unlock()
	if closed || packetContext == nil || packets == nil {
		return session.ErrClosed
	}
	owned := append([]byte(nil), packet...)
	select {
	case packets <- owned:
		return nil
	case <-ctx.Done():
		zeroNativeBytes(owned)
		return ctx.Err()
	case <-packetContext.Done():
		zeroNativeBytes(owned)
		return s.localPacketTerminationError()
	}
}

func (s *nativeSession) finishDuplex(err error) {
	if s == nil {
		return
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return
	}
	if err == nil {
		err = fmt.Errorf("auroracore: native duplex stopped unexpectedly")
	}
	s.pumpErr = err
	cancel := s.cancel
	established := s.established
	s.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	if established != nil {
		_ = established.Close()
	}
}

func (s *nativeSession) localPacketTerminationError() error {
	if s == nil {
		return session.ErrClosed
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.pumpErr != nil {
		return s.pumpErr
	}
	return session.ErrClosed
}

func (r *nativeSessionRegistry) lookup(handle uint64) (*nativeSession, error) {
	if r == nil || handle == 0 {
		return nil, fmt.Errorf("auroracore: native session handle is invalid")
	}
	r.mu.Lock()
	session := r.sessions[handle]
	r.mu.Unlock()
	if session == nil {
		return nil, fmt.Errorf("auroracore: native session handle is unknown")
	}
	return session, nil
}

func (r *nativeSessionRegistry) allocateHandleLocked() (uint64, error) {
	for attempts := 0; attempts <= maximumNativeSessions; attempts++ {
		handle := r.next
		r.next++
		if r.next == 0 {
			r.next = 1
		}
		if handle != 0 && r.sessions[handle] == nil {
			return handle, nil
		}
	}
	return 0, fmt.Errorf("auroracore: native session handle space is exhausted")
}

func (r *nativeSessionRegistry) readRandom(output []byte) error {
	if len(output) == 0 {
		return nil
	}
	r.randomMu.Lock()
	defer r.randomMu.Unlock()
	if _, err := io.ReadFull(r.random, output); err != nil {
		return err
	}
	return nil
}

func (s *nativeSession) close() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	if s.issuerTimer != nil {
		s.issuerTimer.Stop()
		s.issuerTimer = nil
	}
	if s.cancel != nil {
		s.cancel()
	}
	zeroNativeProofRequest(&s.request)
	var closeErrors []error
	if s.handshake != nil {
		closeErrors = append(closeErrors, s.handshake.Close())
		s.handshake = nil
	}
	if s.established != nil {
		closeErrors = append(closeErrors, s.established.Close())
		s.established = nil
	}
	s.issuerURL = ""
	s.issuerCarrierPath = ""
	return errors.Join(closeErrors...)
}

func startNativeSession(ctx context.Context, provisioning client.NativeProvisioning, now time.Time) (nativeSessionHandshake, handshake.ClientProofRequest, error) {
	config, err := provisioning.ClientDriverConfig(now, nativePendingProofProvider{})
	if err != nil {
		return nil, handshake.ClientProofRequest{}, fmt.Errorf("auroracore: native client configuration: %w", err)
	}
	driver, err := handshake.NewClientDriver(config)
	if err != nil {
		return nil, handshake.ClientProofRequest{}, fmt.Errorf("auroracore: create native client driver: %w", err)
	}
	opener, err := provisioning.NewHTTP2ClientCarrierOpener(now)
	if err != nil {
		return nil, handshake.ClientProofRequest{}, fmt.Errorf("auroracore: native carrier opener: %w", err)
	}
	return driver.Begin(ctx, opener)
}

type nativePendingProofProvider struct{}

func (nativePendingProofProvider) BuildProofs(context.Context, handshake.ClientProofRequest) (protocol.AdmissionProof, protocol.ReplayProof, error) {
	return protocol.AdmissionProof{}, protocol.ReplayProof{}, fmt.Errorf("auroracore: native proof provider must be deferred")
}

func (w nativeIssuerWork) encode() ([]byte, error) {
	if w.Handle == 0 || len(w.IssuerURL) == 0 || len(w.IssuerURL) > maximumNativeIssuerWorkBytes || len(w.IssuerCarrierPath) == 0 || len(w.IssuerCarrierPath) > maximumNativeIssuerWorkBytes || len(w.RequestBody) == 0 || len(w.RequestBody) > maximumNativeIssuerWorkBytes {
		return nil, fmt.Errorf("auroracore: native issuer work is invalid")
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(w.Handle)
	encoder.WriteOpaque16([]byte(w.IssuerURL))
	encoder.WriteOpaque16([]byte(w.IssuerCarrierPath))
	encoder.WriteOpaque24(w.RequestBody)
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("auroracore: encode native issuer work: %w", err)
	}
	return encoded, nil
}

func decodeNativeHandlePayload(encoded []byte, maximum int) (uint64, []byte, error) {
	if len(encoded) == 0 || len(encoded) > maximum+16 {
		return 0, nil, fmt.Errorf("auroracore: native handle payload size is invalid")
	}
	reader := wire.NewReader(encoded)
	handle := reader.ReadVarint()
	payload := reader.ReadOpaque24()
	if reader.Err() != nil || !reader.EOF() || handle == 0 || len(payload) == 0 || len(payload) > maximum {
		return 0, nil, fmt.Errorf("auroracore: native handle payload is malformed")
	}
	return handle, payload, nil
}

func encodeNativeFrameBlocks(blocks []protocol.FrameBlock) ([]byte, error) {
	encoder := wire.NewEncoder()
	encoder.WriteVarint(uint64(len(blocks)))
	for index := range blocks {
		encoded, err := protocol.Encode(blocks[index])
		if err != nil {
			return nil, fmt.Errorf("auroracore: encode native frame block: %w", err)
		}
		encoder.WriteOpaque24(encoded)
		zeroNativeBytes(encoded)
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("auroracore: encode native frame blocks: %w", err)
	}
	if len(encoded) > maximumNativeSessionPacket {
		zeroNativeBytes(encoded)
		return nil, fmt.Errorf("auroracore: native frame blocks exceed size limit")
	}
	return encoded, nil
}

func encodeNativeLocalPackets(packets [][]byte) ([]byte, error) {
	if len(packets) > maximumNativeLocalPacketQueue {
		return nil, fmt.Errorf("auroracore: native local packet result count exceeds limit")
	}
	encoder := wire.NewEncoder()
	encoder.WriteVarint(uint64(len(packets)))
	for _, packet := range packets {
		if len(packet) == 0 || len(packet) > maximumNativeLocalPacketBytes {
			return nil, fmt.Errorf("auroracore: native local packet is invalid")
		}
		encoder.WriteOpaque24(packet)
	}
	encoded, err := encoder.Bytes()
	if err != nil {
		return nil, fmt.Errorf("auroracore: encode native local packets: %w", err)
	}
	if len(encoded) > maximumNativeLocalPacketResult {
		zeroNativeBytes(encoded)
		return nil, fmt.Errorf("auroracore: native local packet result exceeds size limit")
	}
	return encoded, nil
}

func cloneNativeProofRequest(in handshake.ClientProofRequest) handshake.ClientProofRequest {
	in.AdmissionContextHash = append([]byte(nil), in.AdmissionContextHash...)
	in.HandshakeBindingContext = append([]byte(nil), in.HandshakeBindingContext...)
	in.ReplayWindowID = append([]byte(nil), in.ReplayWindowID...)
	return in
}

func zeroNativeProofRequest(value *handshake.ClientProofRequest) {
	if value == nil {
		return
	}
	zeroNativeBytes(value.AdmissionContextHash)
	zeroNativeBytes(value.HandshakeBindingContext)
	zeroNativeBytes(value.ReplayWindowID)
	*value = handshake.ClientProofRequest{}
}

func zeroNativeAdmissionProof(value *protocol.AdmissionProof) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{value.IssuerID, value.TokenKeyID, value.RelayBucketID, value.TokenScopeID, value.TokenNonce, value.RedemptionContextHash, value.TokenPublicMetadata, value.TokenAuthenticator, value.BindingProof} {
		zeroNativeBytes(field)
	}
	for index := range value.Extensions {
		zeroNativeBytes(value.Extensions[index].Body)
	}
	*value = protocol.AdmissionProof{}
}

func zeroNativeReplayProof(value *protocol.ReplayProof) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{value.TokenRedemptionHash, value.ClientReplayNonce, value.ReplayContextHash, value.ReplayWindowID} {
		zeroNativeBytes(field)
	}
	for index := range value.Extensions {
		zeroNativeBytes(value.Extensions[index].Body)
	}
	*value = protocol.ReplayProof{}
}

func zeroNativeFrameBlock(value *protocol.FrameBlock) {
	if value == nil {
		return
	}
	for index := range value.Frames {
		zeroNativeBytes(value.Frames[index].Payload)
	}
	*value = protocol.FrameBlock{}
}

func zeroNativeFrameBlocks(values []protocol.FrameBlock) {
	for index := range values {
		zeroNativeFrameBlock(&values[index])
	}
}

func zeroNativeLocalPackets(values [][]byte) {
	for index := range values {
		zeroNativeBytes(values[index])
		values[index] = nil
	}
}

func zeroNativeIssuerWork(value *nativeIssuerWork) {
	if value == nil {
		return
	}
	zeroNativeBytes(value.RequestBody)
	*value = nativeIssuerWork{}
}

func zeroNativeProvisioning(value *client.NativeProvisioning) {
	if value == nil {
		return
	}
	for _, field := range [][]byte{value.Descriptor, value.TrustedDescriptorHash, value.Template, value.TemplateAuthorityKey, value.AccessHint, value.PolicyOffer, value.TransportHints, value.RelayRequestHeaders, value.RelayResponseHeaders, value.RelayTrustRoots} {
		zeroNativeBytes(field)
	}
	*value = client.NativeProvisioning{}
}

func zeroNativeBytes(value []byte) {
	for index := range value {
		value[index] = 0
	}
}
