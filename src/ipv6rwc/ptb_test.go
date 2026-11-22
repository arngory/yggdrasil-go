package ipv6rwc

import (
	"bytes"
	"crypto/ed25519"
	"encoding/binary"
	"io"
	"net/url"
	"testing"
	"time"

	iwt "github.com/Arceliar/ironwood/types"
	"github.com/gologme/log"

	"github.com/yggdrasil-network/yggdrasil-go/src/address"
	"github.com/yggdrasil-network/yggdrasil-go/src/config"
	"github.com/yggdrasil-network/yggdrasil-go/src/core"
)

// A packet over the MTU gets Packet Too Big, sent to its source address,
// with its first bytes in it. Only when that source is the sender's own
// (neko): A sends B an oversize packet with C's address as its source, and
// C gets nothing from B. Before, C got A's bytes from B, though A and C
// might not reach each other at all (a server that keeps its peers apart).
func TestReadPCPacketTooBigOnlyToTheSender(t *testing.T) {
	newCore := func(opts ...core.SetupOption) *core.Core {
		cfg := config.GenerateConfig()
		if err := cfg.GenerateSelfSignedCertificate(); err != nil {
			t.Fatal(err)
		}
		c, err := core.New(cfg.Certificate, log.New(io.Discard, "", 0), opts...)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(c.Stop)
		return c
	}
	b := newCore()
	u, _ := url.Parse("tcp://127.0.0.1:0")
	l, err := b.Listen(u, "")
	if err != nil {
		t.Fatal(err)
	}
	u, _ = url.Parse("tcp://" + l.Addr().String())
	a, c := newCore(core.Peer{URI: u.String()}), newCore(core.Peer{URI: u.String()})

	rwc := NewReadWriteCloser(b) // MTU 1280: what B's TUN takes
	go func() {
		buf := make([]byte, 65535)
		for {
			if _, err := rwc.Read(buf); err != nil {
				return
			}
		}
	}()
	// What A and C get from B.
	got := func(n *core.Core) chan []byte {
		ch := make(chan []byte, 64)
		go func() {
			buf := make([]byte, 65535)
			for {
				k, from, err := n.ReadFrom(buf)
				if err != nil {
					return
				}
				if bytes.Equal(from.(iwt.Addr), b.PublicKey()) {
					ch <- append([]byte(nil), buf[:k]...)
				}
			}
		}()
		return ch
	}
	toA, toC := got(a), got(c)

	marker := []byte("A-TO-C-THROUGH-B")
	packet := func(source ed25519.PublicKey) []byte {
		p := make([]byte, 1400)
		p[0] = 0x60
		binary.BigEndian.PutUint16(p[4:], uint16(len(p)-40))
		p[6], p[7] = 59, 64 // no next header
		copy(p[8:24], address.AddrForKey(source)[:])
		copy(p[24:40], address.AddrForKey(b.PublicKey())[:])
		copy(p[40:], marker)
		return p
	}
	// Each a Packet Too Big that carries the marker.
	ptb := func(ch chan []byte, send func(), d time.Duration) bool {
		for end := time.Now().Add(d); time.Now().Before(end); {
			send()
			select {
			case p := <-ch:
				if len(p) > 40 && p[6] == 58 && p[40] == 2 && bytes.Contains(p, marker) {
					return true
				}
			case <-time.After(200 * time.Millisecond):
			}
		}
		return false
	}

	// A's own address: A gets its Packet Too Big.
	if !ptb(toA, func() { _, _ = a.WriteTo(packet(a.PublicKey()), iwt.Addr(b.PublicKey())) }, 20*time.Second) {
		t.Fatal("A's oversize packet got no Packet Too Big")
	}
	// C reaches B too, so that B could send to C.
	if !ptb(toC, func() { _, _ = c.WriteTo(packet(c.PublicKey()), iwt.Addr(b.PublicKey())) }, 20*time.Second) {
		t.Fatal("C's oversize packet got no Packet Too Big")
	}
	// C's address from A: nothing to C.
	if ptb(toC, func() { _, _ = a.WriteTo(packet(c.PublicKey()), iwt.Addr(b.PublicKey())) }, 5*time.Second) {
		t.Fatal("B sent C a Packet Too Big with A's bytes")
	}
}
