package session

import (
	"context"
	"testing"
	"time"

	"github.com/aurora-protocol/aurora-core/packet"
)

// A congested carrier can deliver a peer's KEY_UPDATE_ACK after the bounded
// write drain window has already completed the update on its own. The
// acknowledgement is then redundant rather than a protocol violation, so it
// must be dropped instead of ending the session.
func TestApplicationDropsAcknowledgementArrivingAfterWriteDrain(t *testing.T) {
	client, relay := newKeyUpdateApplicationPair(t)
	defer client.Close()
	defer relay.Close()

	if err := client.InitiateKeyUpdate(context.Background(), 1); err != nil {
		t.Fatal(err)
	}
	updatePacket := nextApplicationPacket(t, client)
	if _, err := relay.HandlePacket(context.Background(), time.Now(), updatePacket); err != nil {
		t.Fatal(err)
	}
	ackPacket := nextApplicationPacket(t, relay)

	late := time.Now().Add(2 * packet.MaxDrainWindow)
	if _, err := client.HandlePacket(context.Background(), late, ackPacket); err != nil {
		t.Fatalf("HandlePacket(late ACK): %v", err)
	}
	if err := client.Err(); err != nil {
		t.Fatalf("late acknowledgement terminated the session: %v", err)
	}
	if !client.writeState.DrainUntil.IsZero() {
		t.Fatalf("write drain outlived its window")
	}
	if err := client.QueueFrames(context.Background(), testFrameBlock(t, 7, []byte("after late ack"))); err != nil {
		t.Fatalf("session stopped sending after a late acknowledgement: %v", err)
	}
}
