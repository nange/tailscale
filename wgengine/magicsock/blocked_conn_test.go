// Copyright (c) Tailscale Inc & contributors
// SPDX-License-Identifier: BSD-3-Clause

package magicsock

import (
	"errors"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"tailscale.com/net/batching"
)

// signaledBlockedConn is a blockForeverConn that reports the first time a
// reader enters its read path, so a test can wait until a receive func is
// parked in it instead of sleeping and hoping.
type signaledBlockedConn struct {
	*blockForeverConn
	entered chan struct{}
	once    sync.Once
}

func (s *signaledBlockedConn) ReadFromUDPAddrPort(b []byte) (int, netip.AddrPort, error) {
	s.once.Do(func() { close(s.entered) })
	return s.blockForeverConn.ReadFromUDPAddrPort(b)
}

// TestBlockedConnReplacementDoesNotStrandReader pins the invariant behind
// installBlockedConnLocked: when the conn a receive func is parked in is
// replaced (a rebind while UDP is disabled: DERP-only via
// TS_DEBUG_ALWAYS_USE_DERP, or js), the conn being replaced has to be closed.
// A receive func parked in the old conn's ReadFromUDPAddrPort only wakes when
// that very conn is closed, and only then does it re-read the current conn (see
// RebindingUDPConn.readFromWithInitPconn). Replacing the conn without closing
// it strands the reader forever, and wireguard-go's Device.Close then blocks in
// netc.stopping.Wait() — which hangs every caller of Server.Close/Client.Close.
func TestBlockedConnReplacementDoesNotStrandReader(t *testing.T) {
	c := &Conn{logf: t.Logf}

	first := &signaledBlockedConn{
		blockForeverConn: newBlockForeverConn(),
		entered:          make(chan struct{}),
	}
	var ruc RebindingUDPConn
	ruc.setConnLocked(first, "", nil)

	// Read exactly like a receive func does: it parks inside the current
	// conn's ReadFromUDPAddrPort until that conn is closed.
	errc := make(chan error, 1)
	go func() {
		_, err := ruc.ReadBatch(make([]byte, 1), []batching.ReceivedPacket{{}})
		errc <- err
	}()

	select {
	case <-first.entered:
	case <-time.After(10 * time.Second):
		t.Fatal("the reader never entered the conn")
	}

	// A rebind replaces the conn the reader is parked in.
	c.installBlockedConnLocked(&ruc, "udp4")
	if cur, ok := ruc.currentConn().(*blockForeverConn); !ok || cur == first.blockForeverConn {
		t.Fatalf("the conn was not replaced: got %T", ruc.currentConn())
	}

	// The reader has to be parked in the replacement now, so closing the
	// current conn releases it. If it were still stranded in the replaced
	// conn, this close could not reach it and the select below would time out.
	if err := ruc.currentConn().Close(); err != nil && !errors.Is(err, net.ErrClosed) {
		t.Fatalf("closing the current conn: %v", err)
	}

	select {
	case err := <-errc:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("reader returned %v, want net.ErrClosed", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("reader is stranded in the replaced conn: closing the current conn did not release it")
	}
}
