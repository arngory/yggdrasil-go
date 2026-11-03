package core

import (
	"context"
	"net"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// TestLinkDialer checks that outgoing links go through the LinkDialer, and that
// names reach it unresolved except for QUIC, which needs an address.
func TestLinkDialer(t *testing.T) {
	for _, tc := range []struct {
		scheme, host, want string
	}{
		{"tcp", "localhost", "localhost"},
		{"tls", "localhost", "localhost"},
		{"ws", "localhost", "localhost"},
		{"quic", "127.0.0.1", "127.0.0.1"},
	} {
		t.Run(tc.scheme, func(t *testing.T) {
			cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
			require_NoError(t, cfgA.GenerateSelfSignedCertificate())
			require_NoError(t, cfgB.GenerateSelfSignedCertificate())
			logger := GetLoggerWithPrefix("", false)

			var mu sync.Mutex
			var dialled []string
			record := func(network, address string) {
				mu.Lock()
				defer mu.Unlock()
				dialled = append(dialled, network+" "+address)
			}
			hook := LinkDialer{
				DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
					record(network, address)
					var d net.Dialer
					return d.DialContext(ctx, network, address)
				},
				ListenPacket: func(ctx context.Context, network, address string) (net.PacketConn, error) {
					record(network, address)
					return net.ListenPacket("udp", ":0")
				},
			}

			nodeA, err := New(cfgA.Certificate, logger)
			require_NoError(t, err)
			defer nodeA.Stop()
			nodeB, err := New(cfgB.Certificate, logger, hook)
			require_NoError(t, err)
			defer nodeB.Stop()

			listener, err := nodeA.Listen(&url.URL{Scheme: tc.scheme, Host: "127.0.0.1:0"}, "")
			require_NoError(t, err)
			_, port, err := net.SplitHostPort(listener.Addr().String())
			require_NoError(t, err)
			peer := &url.URL{Scheme: tc.scheme, Host: net.JoinHostPort(tc.host, port)}
			require_NoError(t, nodeB.CallPeer(peer, ""))

			deadline := time.Now().Add(5 * time.Second)
			for !peered(nodeA, nodeB) {
				if time.Now().After(deadline) {
					t.Fatal("no link through the LinkDialer")
				}
				time.Sleep(50 * time.Millisecond)
			}

			network := "tcp"
			if tc.scheme == "quic" {
				network = "udp"
			}
			mu.Lock()
			defer mu.Unlock()
			if len(dialled) == 0 {
				t.Fatal("the LinkDialer was not used")
			}
			want := network + " " + net.JoinHostPort(tc.want, port)
			if dialled[0] != want {
				t.Fatalf("dialled %q, want %q", dialled[0], want)
			}
		})
	}
}

func peered(nodeA, nodeB *Core) bool {
	up := func(c *Core) bool {
		for _, p := range c.GetPeers() {
			if p.Up {
				return true
			}
		}
		return false
	}
	return up(nodeA) && up(nodeB)
}
