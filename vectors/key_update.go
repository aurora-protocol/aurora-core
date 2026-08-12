package vectors

import (
	"encoding/hex"
	"fmt"

	"github.com/aurora-protocol/aurora-core/packet"
	"github.com/aurora-protocol/aurora-core/protocol"
	"github.com/aurora-protocol/aurora-core/registry"
	"github.com/aurora-protocol/aurora-core/wire"
)

type KeyUpdateRealCryptoBundle struct {
	KeyUpdateFrame         string
	KeyUpdateFrameBlock    string
	KeyUpdateACK           string
	KeyUpdateACKFrameBlock string
	KeyUpdateContext       string
	CurrentAppSecret       string
	NextAppSecret          string
	NextKey                string
	NextIV                 string
}

func GenerateKeyUpdateRealCryptoBundle() (KeyUpdateRealCryptoBundle, error) {
	const suite = registry.SuiteHybrid768P256AESGCM

	currentAppSecret := repeated(0xd0, 48)
	update := protocol.KeyUpdate{
		RouteInstanceID: 2,
		HopLayer:        1,
		Direction:       0,
		OldKeyPhase:     0,
		NewKeyPhase:     1,
		UpdateNonce:     repeated(0xd1, 16),
		AckRequired:     true,
		UpdateReason:    1,
	}
	context, err := packet.KeyUpdateContext(update)
	if err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	result, err := packet.ApplyReceivedKeyUpdate(suite, currentAppSecret, update, repeated(0xd2, 16))
	if err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	defer result.Destroy()
	if result.ACK == nil {
		return KeyUpdateRealCryptoBundle{}, fmt.Errorf("vectors: KEY_UPDATE did not produce required ACK")
	}
	encodedUpdate, err := wire.Encode(update)
	if err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	updateFrame := protocol.AuroraFrame{
		FrameType: registry.FrameKeyUpdate,
		Payload:   encodedUpdate,
	}
	if err := protocol.ValidateKeyUpdateFrame(updateFrame); err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	encodedUpdateBlock, err := wire.Encode(protocol.FrameBlock{Frames: []protocol.AuroraFrame{updateFrame}})
	if err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	encodedACK, err := wire.Encode(*result.ACK)
	if err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	ackFrame := protocol.AuroraFrame{
		FrameType: registry.FrameKeyUpdateAck,
		Payload:   encodedACK,
	}
	if err := protocol.ValidateKeyUpdateFrame(ackFrame); err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	encodedACKBlock, err := wire.Encode(protocol.FrameBlock{Frames: []protocol.AuroraFrame{ackFrame}})
	if err != nil {
		return KeyUpdateRealCryptoBundle{}, err
	}
	return KeyUpdateRealCryptoBundle{
		KeyUpdateFrame:         hex.EncodeToString(encodedUpdate),
		KeyUpdateFrameBlock:    hex.EncodeToString(encodedUpdateBlock),
		KeyUpdateACK:           hex.EncodeToString(encodedACK),
		KeyUpdateACKFrameBlock: hex.EncodeToString(encodedACKBlock),
		KeyUpdateContext:       hex.EncodeToString(context),
		CurrentAppSecret:       hex.EncodeToString(currentAppSecret),
		NextAppSecret:          hex.EncodeToString(result.Next.AppSecret),
		NextKey:                hex.EncodeToString(result.Next.Key),
		NextIV:                 hex.EncodeToString(result.Next.IV),
	}, nil
}
