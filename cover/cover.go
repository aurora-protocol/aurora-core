package cover

import (
	"bytes"
	"fmt"

	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/trust"
)

type ValidationOptions struct {
	NowUnix       uint64
	MaxFutureSkew uint64
}

func ValidateTemplate(tpl protocol.CoverTemplate, opts ValidationOptions) error {
	if tpl.TemplateVersion != registry.Version20 {
		return fmt.Errorf("cover: unsupported template version 0x%x", tpl.TemplateVersion)
	}
	if err := trust.ValidateCoverTemplateTime(tpl, opts.NowUnix, opts.MaxFutureSkew); err != nil {
		return err
	}
	commitment, err := trust.CoverOriginCommitment(tpl)
	if err != nil {
		return err
	}
	if !bytes.Equal(commitment, tpl.CoverOriginCommitment) {
		return fmt.Errorf("cover: origin commitment mismatch")
	}
	if err := validatePreludeEnvelope(tpl.PreludeEnvelope); err != nil {
		return err
	}
	if err := validateCapsuleEnvelope(tpl); err != nil {
		return err
	}
	seenClasses := make(map[uint64]struct{}, len(tpl.RequestClasses))
	gatewayCarrier := false
	for _, class := range tpl.RequestClasses {
		if _, ok := seenClasses[class.ClassID]; ok {
			return fmt.Errorf("cover: duplicate request class id 0x%x", class.ClassID)
		}
		seenClasses[class.ClassID] = struct{}{}
		if err := trust.ValidateRequestClass(class); err != nil {
			return err
		}
		if class.ClassType == registry.RequestGatewayOwnedSlot && (class.MayCarryPrelude || class.MayCarryCapsule) {
			gatewayCarrier = true
		}
	}
	if !gatewayCarrier {
		return fmt.Errorf("cover: no gateway-owned request class can carry protocol material")
	}
	return nil
}

func SelectGatewayOwnedClass(tpl protocol.CoverTemplate, classID uint64, needCapsule bool) (protocol.RequestClass, error) {
	for _, class := range tpl.RequestClasses {
		if class.ClassID != classID {
			continue
		}
		if class.ClassType != registry.RequestGatewayOwnedSlot {
			return protocol.RequestClass{}, fmt.Errorf("cover: request class is not gateway owned")
		}
		if needCapsule && !class.MayCarryCapsule {
			return protocol.RequestClass{}, fmt.Errorf("cover: request class cannot carry capsule")
		}
		if !needCapsule && !class.MayCarryPrelude {
			return protocol.RequestClass{}, fmt.Errorf("cover: request class cannot carry prelude")
		}
		return class, nil
	}
	return protocol.RequestClass{}, fmt.Errorf("cover: request class not found")
}

func validatePreludeEnvelope(p protocol.PreludeEnvelope) error {
	if p.MaxRequestBodySize < p.MinRequestBodySize {
		return fmt.Errorf("cover: prelude request size interval is invalid")
	}
	if p.MaxResponseBodySize < p.MinResponseBodySize {
		return fmt.Errorf("cover: prelude response size interval is invalid")
	}
	if p.MaxRequestBodySize < 1536 {
		return fmt.Errorf("cover: prelude request envelope too small")
	}
	if p.MaxResponseBodySize < 6144 {
		return fmt.Errorf("cover: prelude response envelope too small")
	}
	return nil
}

func validateCapsuleEnvelope(tpl protocol.CoverTemplate) error {
	if tpl.CapsuleEnvelope.MaxCapsuleBodySize < tpl.CapsuleEnvelope.MinCapsuleBodySize {
		return fmt.Errorf("cover: capsule body size interval is invalid")
	}
	needsLocalConsume := false
	for _, class := range tpl.RequestClasses {
		if class.ClassType == registry.RequestGatewayOwnedSlot && class.MayCarryCapsule {
			needsLocalConsume = true
			break
		}
	}
	if needsLocalConsume && !tpl.CapsuleEnvelope.ConsumeFailedBodyLocally {
		return fmt.Errorf("cover: capsule failures must be consumed locally")
	}
	return nil
}
