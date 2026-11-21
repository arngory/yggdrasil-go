package core

import (
	"bytes"
	"crypto/ed25519"
	"net"
	"net/url"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// TestPQSessions: two nodes with PQSessions get a PQ session, and one with them talks to one without in a classic
// session (neko).
func TestPQSessions(t *testing.T) {
	logger := GetLoggerWithPrefix("", false)
	cfgA, cfgB, cfgC := config.GenerateConfig(), config.GenerateConfig(), config.GenerateConfig()
	require_NoError(t, cfgA.GenerateSelfSignedCertificate())
	require_NoError(t, cfgB.GenerateSelfSignedCertificate())
	require_NoError(t, cfgC.GenerateSelfSignedCertificate())

	nodeA, err := New(cfgA.Certificate, logger, PQSessions{})
	require_NoError(t, err)
	defer nodeA.Stop()
	nodeB, err := New(cfgB.Certificate, logger, PQSessions{})
	require_NoError(t, err)
	defer nodeB.Stop()
	nodeC, err := New(cfgC.Certificate, logger)
	require_NoError(t, err)
	defer nodeC.Stop()

	u, err := url.Parse("tcp://localhost:0")
	require_NoError(t, err)
	l, err := nodeA.Listen(u, "")
	require_NoError(t, err)
	u, err = url.Parse("tcp://" + l.Addr().String())
	require_NoError(t, err)
	require_NoError(t, nodeB.AddPeer(u, ""))
	require_NoError(t, nodeC.AddPeer(u, ""))
	require_True(t, WaitConnected(nodeA, nodeB))
	require_True(t, WaitConnected(nodeA, nodeC))

	heard := make(chan net.Addr, 64)
	for _, n := range []*Core{nodeA, nodeB, nodeC} {
		go func(conn net.PacketConn) {
			var buf [1024]byte
			for t.Context().Err() == nil {
				if _, from, err := conn.ReadFrom(buf[:]); err == nil {
					select {
					case heard <- from:
					default:
					}
				}
			}
		}(n.PacketConn)
	}

	session := func(n *Core, key ed25519.PublicKey) string {
		for _, s := range n.PacketConn.Debug.GetSessions() {
			if bytes.Equal(s.Key, key) {
				if s.PQ {
					return "pq"
				}
				return "classic"
			}
		}
		return "none"
	}
	want := map[*Core]string{nodeB: "pq", nodeC: "classic"}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		done := true
		for n, w := range want {
			_, _ = nodeA.PacketConn.WriteTo([]byte("hello"), n.PacketConn.LocalAddr())
			_, _ = n.PacketConn.WriteTo([]byte("back"), nodeA.PacketConn.LocalAddr())
			if session(nodeA, n.public) != w || session(n, nodeA.public) != w {
				done = false
			}
		}
		if done {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("sessions in 20 s: A-B %s/%s (want pq), A-C %s/%s (want classic)",
				session(nodeA, nodeB.public), session(nodeB, nodeA.public), session(nodeA, nodeC.public), session(nodeC, nodeA.public))
		}
	}
}
