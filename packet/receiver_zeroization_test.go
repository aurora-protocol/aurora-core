package packet

import (
	"bytes"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/registry"
)

func cachedReceiverProtectorForZeroizationTest(t *testing.T) (*Receiver, receiverPacketNumberSpace, *Protector) {
	t.Helper()
	receiver := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	state := transactionalDirectionState()
	defer state.Destroy()
	packet := receiverMaterialPacket()
	if _, err := receiver.PrepareOpenWithDirectionState(packet, &state, registry.SuiteHybrid768AESGCM, time.Now()); err == nil {
		t.Fatal("garbage packet unexpectedly authenticated")
	}
	space := packetNumberSpace(packet)
	protector := receiver.directionProtectors[space]
	if protector == nil {
		t.Fatal("packet authentication did not cache its direction protector")
	}
	return receiver, space, protector
}

func TestReceiverForgetPacketNumberSpaceZeroesCachedProtector(t *testing.T) {
	receiver, space, idle := cachedReceiverProtectorForZeroizationTest(t)
	idleKey := idle.Key
	idleIV := idle.StaticIV
	if bytes.Equal(idleKey, make([]byte, len(idleKey))) || bytes.Equal(idleIV, make([]byte, len(idleIV))) {
		t.Fatal("cached protector did not retain test traffic material before eviction")
	}

	receiver.ForgetPacketNumberSpace(space.RouteInstanceID, space.HopLayer, space.Direction, space.KeyPhase)
	if receiver.directionProtectors[space] != nil {
		t.Fatal("forgotten packet-number space retained its cached protector")
	}
	if !bytes.Equal(idleKey, make([]byte, len(idleKey))) || !bytes.Equal(idleIV, make([]byte, len(idleIV))) {
		t.Fatal("forgotten packet-number space retained idle traffic material")
	}
}

func TestReceiverDefersRetiredProtectorZeroizationUntilOpenReleases(t *testing.T) {
	receiver, space, active := cachedReceiverProtectorForZeroizationTest(t)
	activeKey := active.Key
	activeIV := active.StaticIV
	receiver.mu.Lock()
	held, err := receiver.acquireProtectorLocked(active)
	receiver.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	receiver.ForgetPacketNumberSpace(space.RouteInstanceID, space.HopLayer, space.Direction, space.KeyPhase)
	if bytes.Equal(activeKey, make([]byte, len(activeKey))) || bytes.Equal(activeIV, make([]byte, len(activeIV))) {
		t.Fatal("in-flight protector was zeroed before its open released it")
	}
	receiver.releaseProtector(held)
	if !bytes.Equal(activeKey, make([]byte, len(activeKey))) || !bytes.Equal(activeIV, make([]byte, len(activeIV))) {
		t.Fatal("retired protector retained traffic material after its open released it")
	}
	if len(receiver.protectorUses) != 0 || len(receiver.retiredProtectors) != 0 {
		t.Fatalf("protector ownership tracking leaked: uses=%d retired=%d", len(receiver.protectorUses), len(receiver.retiredProtectors))
	}
}

func TestReceiverDestroyDefersBaseProtectorZeroizationUntilOpenReleases(t *testing.T) {
	receiver := NewReceiver(ReceiverConfig{Protector: receiverConfigProtector()})
	baseKey := receiver.protector.Key
	baseIV := receiver.protector.StaticIV
	receiver.mu.Lock()
	held, err := receiver.acquireProtectorLocked(&receiver.protector)
	receiver.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	receiver.Destroy()
	if bytes.Equal(baseKey, make([]byte, len(baseKey))) || bytes.Equal(baseIV, make([]byte, len(baseIV))) {
		t.Fatal("receiver destroy zeroed a protector still held by an in-flight open")
	}
	receiver.releaseProtector(held)
	if !bytes.Equal(baseKey, make([]byte, len(baseKey))) || !bytes.Equal(baseIV, make([]byte, len(baseIV))) {
		t.Fatal("destroyed receiver retained base traffic material after its open released it")
	}
	if len(receiver.protectorUses) != 0 || len(receiver.retiredProtectors) != 0 {
		t.Fatalf("destroyed receiver ownership tracking leaked: uses=%d retired=%d", len(receiver.protectorUses), len(receiver.retiredProtectors))
	}
}
