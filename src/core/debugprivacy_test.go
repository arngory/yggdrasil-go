package core

import (
	"net/url"
	"testing"
	"time"

	"github.com/yggdrasil-network/yggdrasil-go/src/config"
)

// TestDebugPrivacy: a node with DebugPrivacy leaves remote getSelf, getPeers
// and getTree unanswered, but its own requests to others still get answers.
func TestDebugPrivacy(t *testing.T) {
	logger := GetLoggerWithPrefix("", false)
	cfgA, cfgB := config.GenerateConfig(), config.GenerateConfig()
	require_NoError(t, cfgA.GenerateSelfSignedCertificate())
	require_NoError(t, cfgB.GenerateSelfSignedCertificate())

	nodeA, err := New(cfgA.Certificate, logger, DebugPrivacy(true))
	require_NoError(t, err)
	defer nodeA.Stop()
	nodeB, err := New(cfgB.Certificate, logger)
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

	// Proto packets are handled inside ReadFrom, as the TUN reader would.
	for _, n := range []*Core{nodeA, nodeB} {
		go func() {
			buf := make([]byte, 65535)
			for {
				if _, _, err := n.ReadFrom(buf); err != nil {
					return
				}
			}
		}()
	}

	var keyA, keyB keyArray
	copy(keyA[:], nodeA.PublicKey())
	copy(keyB[:], nodeB.PublicKey())

	ask := func(from *Core, to keyArray, send func(*protoHandler, keyArray, func([]byte))) bool {
		got := make(chan struct{}, 1)
		send(&from.proto, to, func([]byte) { got <- struct{}{} })
		select {
		case <-got:
			return true
		case <-time.After(3 * time.Second):
			return false
		}
	}
	requests := map[string]func(*protoHandler, keyArray, func([]byte)){
		"getSelf":  (*protoHandler).sendGetSelfRequest,
		"getPeers": (*protoHandler).sendGetPeersRequest,
		"getTree":  (*protoHandler).sendGetTreeRequest,
	}
	for name, send := range requests {
		if ask(nodeB, keyA, send) {
			t.Errorf("%s: the private node answered", name)
		}
		if !ask(nodeA, keyB, send) {
			t.Errorf("%s: the private node got no answer to its own request", name)
		}
	}
}
