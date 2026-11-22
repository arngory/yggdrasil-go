package core

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
)

func (c *Core) _applyOption(opt SetupOption) (err error) {
	switch v := opt.(type) {
	case Peer:
		u, err := url.Parse(v.URI)
		if err != nil {
			return fmt.Errorf("unable to parse peering URI: %w", err)
		}
		err = c.links.add(u, v.SourceInterface, linkTypePersistent)
		switch err {
		case ErrLinkAlreadyConfigured:
			// Don't return this error, otherwise we'll panic at startup
			// if there are multiple of the same peer configured
			return nil
		default:
			return err
		}
	case ListenAddress:
		c.config._listeners[v] = struct{}{}
	case PeerFilter:
		c.config.peerFilter = v
	case NodeInfo:
		c.config.nodeinfo = v
	case NodeInfoPrivacy:
		c.config.nodeinfoPrivacy = v
	case AllowedPublicKey:
		pk := [32]byte{}
		copy(pk[:], v)
		c.config._allowedPublicKeys[pk] = struct{}{}
	case GroupPassword:
		c.config.groupPassword = string(v)
	case LinkDialer:
		c.config.linkDialer = v
	case DebugPrivacy:
		c.config.debugPrivacy = v
	case PQSessions:
		c.config.pq = &v
	}
	return
}

type SetupOption interface {
	isSetupOption()
}

type ListenAddress string
type Peer struct {
	URI             string
	SourceInterface string
}
type NodeInfo map[string]any
type NodeInfoPrivacy bool
type AllowedPublicKey ed25519.PublicKey
type PeerFilter func(net.IP) bool
type GroupPassword string

// LinkDialer opens the outgoing peering connections when set (neko addition): a program
// embedding the core routes them through its own dialer, for example to keep them out of
// a VPN it provides. Pass it before any Peer. Link-local peers keep the plain dialer.
type LinkDialer struct {
	DialContext  func(ctx context.Context, network, address string) (net.Conn, error)
	ListenPacket func(ctx context.Context, network, address string) (net.PacketConn, error)
	// TLSClient, if set, runs the client handshake of tls:// links dialled through
	// DialContext (neko: a browser ClientHello); nil uses crypto/tls.
	TLSClient func(ctx context.Context, conn net.Conn, config *tls.Config) (net.Conn, error)
}

// DebugPrivacy, when true, leaves remote getSelf, getPeers and getTree
// requests unanswered (neko addition). Without it any node with a session to
// this one learns the keys of all its peers (getPeers) and its tree (getTree):
// a server whose peers are its users' devices would list them to anyone. The
// node can still send these requests itself and gets the answers.
type DebugPrivacy bool

// PQSessions turns on ironwood's hybrid post-quantum sessions (neko addition; arngory/ironwood, and Niko's
// docs/design/ironwood-pq.md): a node with them and one without still talk, in classic sessions; two with them replace
// the classic session with a PQ one. Required reports the keys a session with must be PQ (classic refused both ways);
// nil: none. Without the option, the node's sessions are the classic ones: what it sends of its own is upstream's,
// byte for byte, and its replies are as ironwood's PQConfig describes (an init in reply to traffic at most once in 3 s
// a key, a repeated init answered at most once a second, a classic init in reply to PQ traffic from a key with no
// session, which upstream's nodes never send). AnswerOnly: PQ in answer only (ironwood's PQConfig.AnswerOnly): the
// node starts no PQ session itself, answers the ones its peers start, and holds no key to PQ anew; a key held to PQ
// (Required, or held before) it still starts with. Off, answer only, on: no option, AnswerOnly, the option alone.
type PQSessions struct {
	Required   func(key ed25519.PublicKey) bool
	AnswerOnly bool
}

func (a ListenAddress) isSetupOption()    {}
func (a Peer) isSetupOption()             {}
func (a NodeInfo) isSetupOption()         {}
func (a NodeInfoPrivacy) isSetupOption()  {}
func (a AllowedPublicKey) isSetupOption() {}
func (a PeerFilter) isSetupOption()       {}
func (a GroupPassword) isSetupOption()    {}
func (a LinkDialer) isSetupOption()       {}
func (a DebugPrivacy) isSetupOption()     {}
func (a PQSessions) isSetupOption()       {}
