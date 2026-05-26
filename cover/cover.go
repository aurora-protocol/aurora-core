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
	privateCarrier := false
	for _, class := range tpl.RequestClasses {
		if _, ok := seenClasses[class.ClassID]; ok {
			return fmt.Errorf("cover: duplicate request class id 0x%x", class.ClassID)
		}
		seenClasses[class.ClassID] = struct{}{}
		if err := trust.ValidateRequestClass(class); err != nil {
			return err
		}
		if class.MayCarryPrelude || class.MayCarryCapsule {
			if !isKnownMethodFamily(class.AllowedMethodFamily) {
				return fmt.Errorf("cover: protocol carrier has invalid method family 0x%x", class.AllowedMethodFamily)
			}
			if class.ClassType == registry.RequestSidecarOriginSlot && class.AllowedMethodFamily != registry.MethodShadowOrigin {
				return fmt.Errorf("cover: sidecar-origin carrier requires shadow-origin method family")
			}
		}
		if isPrivateCarrierClass(class) {
			privateCarrier = true
		}
	}
	if !privateCarrier {
		return fmt.Errorf("cover: no private request class can carry protocol material")
	}
	return nil
}

func SelectCarrierClass(tpl protocol.CoverTemplate, classID uint64, method uint64, needCapsule bool) (protocol.RequestClass, error) {
	if method == registry.MethodShadowOrigin {
		return SelectPrivateCarrierClass(tpl, classID, method, needCapsule)
	}
	class, err := SelectGatewayOwnedClass(tpl, classID, needCapsule)
	if err != nil {
		return protocol.RequestClass{}, err
	}
	if class.AllowedMethodFamily != method {
		return protocol.RequestClass{}, fmt.Errorf("cover: request class method family 0x%x does not match selected method 0x%x", class.AllowedMethodFamily, method)
	}
	return class, nil
}

func SelectPrivateCarrierClass(tpl protocol.CoverTemplate, classID uint64, method uint64, needCapsule bool) (protocol.RequestClass, error) {
	for _, class := range tpl.RequestClasses {
		if class.ClassID != classID {
			continue
		}
		if !isPrivateCarrierClass(class) {
			return protocol.RequestClass{}, fmt.Errorf("cover: request class is not a private carrier slot")
		}
		if class.AllowedMethodFamily != method {
			return protocol.RequestClass{}, fmt.Errorf("cover: request class method family 0x%x does not match selected method 0x%x", class.AllowedMethodFamily, method)
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

func isPrivateCarrierClass(class protocol.RequestClass) bool {
	if !class.MayCarryPrelude && !class.MayCarryCapsule {
		return false
	}
	return class.ClassType == registry.RequestGatewayOwnedSlot || class.ClassType == registry.RequestSidecarOriginSlot
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

func isKnownMethodFamily(method uint64) bool {
	switch method {
	case registry.MethodWebH2Stream,
		registry.MethodWebH1WS,
		registry.MethodShadowOrigin,
		registry.MethodWebH3Stream,
		registry.MethodWebH3ExtDgram,
		registry.MethodMasqueConnectIP,
		registry.MethodMasqueConnectUDP,
		registry.MethodDirectQUICLab:
		return true
	default:
		return false
	}
}

func validateCapsuleEnvelope(tpl protocol.CoverTemplate) error {
	if tpl.CapsuleEnvelope.MaxCapsuleBodySize < tpl.CapsuleEnvelope.MinCapsuleBodySize {
		return fmt.Errorf("cover: capsule body size interval is invalid")
	}
	needsLocalConsume := false
	for _, class := range tpl.RequestClasses {
		if (class.ClassType == registry.RequestGatewayOwnedSlot || class.ClassType == registry.RequestSidecarOriginSlot) && class.MayCarryCapsule {
			needsLocalConsume = true
			break
		}
	}
	if needsLocalConsume && !tpl.CapsuleEnvelope.ConsumeFailedBodyLocally {
		return fmt.Errorf("cover: capsule failures must be consumed locally")
	}
	return nil
}
