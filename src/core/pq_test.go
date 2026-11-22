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
		for _, s := range n.Debug.GetSessions() {
			if bytes.Equal(s.Key, key) {
				switch {
				case s.PQ && s.PQConfirmed:
					return "pq"
				case s.PQ:
					// a PQ session the peer's traffic has not opened under yet: the classic one beside carries it
					return "pq, unconfirmed"
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
			_, _ = nodeA.PacketConn.WriteTo([]byte("hello"), n.LocalAddr())
			_, _ = n.PacketConn.WriteTo([]byte("back"), nodeA.LocalAddr())
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

// TestPQSessionsAnswerOnly: two nodes with PQ in answer only start no PQ session with each other (neither starts
// one): they talk in a classic session, no PQ session ever up (neko).
func TestPQSessionsAnswerOnly(t *testing.T) {
	logger := GetLoggerWithPrefix("", false)
	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	require_NoError(t, cfgA.GenerateSelfSignedCertificate())
	require_NoError(t, cfgB.GenerateSelfSignedCertificate())
	nodeA, err := New(cfgA.Certificate, logger, PQSessions{AnswerOnly: true})
	require_NoError(t, err)
	defer nodeA.Stop()
	nodeB, err := New(cfgB.Certificate, logger, PQSessions{AnswerOnly: true})
	require_NoError(t, err)
	defer nodeB.Stop()

	u, err := url.Parse("tcp://localhost:0")
	require_NoError(t, err)
	l, err := nodeA.Listen(u, "")
	require_NoError(t, err)
	u, err = url.Parse("tcp://" + l.Addr().String())
	require_NoError(t, err)
	require_NoError(t, nodeB.AddPeer(u, ""))
	require_True(t, WaitConnected(nodeA, nodeB))
	// each node's packets read, as an application would: unread, the delivery holds the sessions up
	for _, n := range []*Core{nodeA, nodeB} {
		go func(conn net.PacketConn) {
			var buf [1024]byte
			for t.Context().Err() == nil {
				_, _, _ = conn.ReadFrom(buf[:])
			}
		}(n.PacketConn)
	}

	classic := func(n *Core, key ed25519.PublicKey) bool {
		for _, s := range n.Debug.GetSessions() {
			if bytes.Equal(s.Key, key) {
				return !s.PQ
			}
		}
		return false
	}
	for deadline := time.Now().Add(20 * time.Second); ; time.Sleep(100 * time.Millisecond) {
		_, _ = nodeA.PacketConn.WriteTo([]byte("hello"), nodeB.LocalAddr())
		_, _ = nodeB.PacketConn.WriteTo([]byte("back"), nodeA.LocalAddr())
		if classic(nodeA, nodeB.public) && classic(nodeB, nodeA.public) {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no classic session both ways in 20 s")
		}
	}
	// some more traffic: neither starts PQ on it
	for range 20 {
		_, _ = nodeA.PacketConn.WriteTo([]byte("hello"), nodeB.LocalAddr())
		_, _ = nodeB.PacketConn.WriteTo([]byte("back"), nodeA.LocalAddr())
		time.Sleep(100 * time.Millisecond)
	}
	if a, b := nodeA.PQSessionCount(), nodeB.PQSessionCount(); a != 0 || b != 0 {
		t.Fatalf("PQ sessions up in answer only: A %d, B %d", a, b)
	}
}

// TestPQSessionsAnswerNodeOnClient: a node in answer only and a client with PQ on (Niko's default pair) get a PQ
// session with either end holding the lower key, the classic session first or not, and traffic both ways all along
// (ironwood round 8: the higher key starts when the lower one does not; the switch takes the classic traffic in
// flight) (neko).
func TestPQSessionsAnswerNodeOnClient(t *testing.T) {
	for _, clientLower := range []bool{true, false} {
		t.Run(map[bool]string{true: "client lower", false: "client higher"}[clientLower], func(t *testing.T) {
			logger := GetLoggerWithPrefix("", false)
			var cfgN, cfgC *config.NodeConfig
			for {
				cfgN, cfgC = config.GenerateConfig(), config.GenerateConfig()
				require_NoError(t, cfgN.GenerateSelfSignedCertificate())
				require_NoError(t, cfgC.GenerateSelfSignedCertificate())
				lower := bytes.Compare(cfgC.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey),
					cfgN.Certificate.PrivateKey.(ed25519.PrivateKey).Public().(ed25519.PublicKey)) < 0
				if lower == clientLower {
					break
				}
			}
			node, err := New(cfgN.Certificate, logger, PQSessions{AnswerOnly: true})
			require_NoError(t, err)
			defer node.Stop()
			client, err := New(cfgC.Certificate, logger, PQSessions{})
			require_NoError(t, err)
			defer client.Stop()
			u, err := url.Parse("tcp://localhost:0")
			require_NoError(t, err)
			l, err := node.Listen(u, "")
			require_NoError(t, err)
			u, err = url.Parse("tcp://" + l.Addr().String())
			require_NoError(t, err)
			require_NoError(t, client.AddPeer(u, ""))
			require_True(t, WaitConnected(node, client))
			for _, n := range []*Core{node, client} {
				go func(conn net.PacketConn) {
					var buf [1024]byte
					for t.Context().Err() == nil {
						_, _, _ = conn.ReadFrom(buf[:])
					}
				}(n.PacketConn)
			}
			pq := func(n *Core, key ed25519.PublicKey) bool {
				for _, s := range n.Debug.GetSessions() {
					if bytes.Equal(s.Key, key) {
						return s.PQ && s.PQConfirmed
					}
				}
				return false
			}
			for deadline := time.Now().Add(20 * time.Second); !pq(client, node.public) || !pq(node, client.public); time.Sleep(100 * time.Millisecond) {
				if time.Now().After(deadline) {
					t.Fatalf("no PQ session both ways in 20 s (client %v, node %v)", pq(client, node.public), pq(node, client.public))
				}
				_, _ = client.PacketConn.WriteTo([]byte("hello"), node.LocalAddr())
				_, _ = node.PacketConn.WriteTo([]byte("back"), client.LocalAddr())
			}
		})
	}
}
