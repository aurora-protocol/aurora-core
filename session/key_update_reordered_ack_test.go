package session

import (
	"context"
	"testing"
	"time"
)

// A peer that acknowledges our KEY_UPDATE and initiates its own sends the
// acknowledgement first, but the network may deliver its KEY_UPDATE first. The
// acknowledgement then arrives under the drained previous read phase, which
// still authenticates, so it must be applied instead of ending the session.
func TestApplicationAcceptsAcknowledgementReorderedBehindPeerKeyUpdate(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	clientUpdate := nextApplicationPacket(t, client)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), clientUpdate); err != nil {
		t.Fatal(err)
	}
	if err := relay.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}

	ackPacket := nextApplicationPacket(t, relay)
	relayUpdate := nextApplicationPacket(t, relay)
	ackHeader := decodeApplicationPacket(t, ackPacket)
	updateHeader := decodeApplicationPacket(t, relayUpdate)
	if ackHeader.KeyPhase != 0 || updateHeader.KeyPhase != 0 {
		t.Fatalf("relay control packet phases = %d/%d, want 0/0", ackHeader.KeyPhase, updateHeader.KeyPhase)
	}

	if _, err := client.HandlePacket(context.Background(), time.Now(), relayUpdate); err != nil {
		t.Fatalf("HandlePacket(peer update): %v", err)
	}
	if client.readState.KeyPhase != 1 {
		t.Fatalf("client read phase = %d, want 1", client.readState.KeyPhase)
	}

	if _, err := client.HandlePacket(context.Background(), time.Now(), ackPacket); err != nil {
		t.Fatalf("HandlePacket(reordered ACK): %v", err)
	}
	if err := client.Err(); err != nil {
		t.Fatalf("reordered acknowledgement terminated the session: %v", err)
	}
	if !client.writeState.DrainUntil.IsZero() {
		t.Fatalf("reordered acknowledgement did not finish the write drain")
	}
}
