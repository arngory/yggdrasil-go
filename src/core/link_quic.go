package core

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/url"
	"time"

	"github.com/Arceliar/phony"
	"github.com/quic-go/quic-go"
)

type linkQUIC struct {
	phony.Inbox
	*links
	tlsconfig  *tls.Config
	quicconfig *quic.Config
}

type linkQUICStream struct {
	*quic.Conn
	*quic.Stream
	packetConn net.PacketConn // from LinkDialer, closed with the stream (neko)
}

type linkQUICListener struct {
	*quic.Listener
	ch <-chan *linkQUICStream
}

func (l *linkQUICListener) Accept() (net.Conn, error) {
	qs := <-l.ch
	if qs == nil {
		return nil, context.Canceled
	}
	return qs, nil
}

func (l *links) newLinkQUIC() *linkQUIC {
	lt := &linkQUIC{
		links:     l,
		tlsconfig: l.core.config.tls.Clone(),
		quicconfig: &quic.Config{
			MaxIdleTimeout:        time.Minute,
			KeepAlivePeriod:       time.Second * 20,
			TokenStore:            quic.NewLRUTokenStore(255, 255),
			MaxIncomingStreams:    1,
			MaxIncomingUniStreams: -1,
		},
	}
	return lt
}

func (l *linkQUIC) dial(ctx context.Context, url *url.URL, info linkInfo, options linkOptions) (net.Conn, error) {
	tlsconfig := l.tlsconfig.Clone()
	return l.findSuitableIP(url, func(hostname string, ip net.IP, port int) (net.Conn, error) {
		tlsconfig.ServerName = hostname
		tlsconfig.MinVersion = tls.VersionTLS12
		tlsconfig.MaxVersion = tls.VersionTLS13
		if sni := options.tlsSNI; sni != "" {
			tlsconfig.ServerName = sni
		}
		hostport := net.JoinHostPort(ip.String(), fmt.Sprintf("%d", port))
		var qc *quic.Conn
		var packetConn net.PacketConn
		var err error
		if hook := l.core.config.linkDialer.ListenPacket; hook != nil && !ip.IsLinkLocalUnicast() {
			packetConn, err = hook(ctx, "udp", hostport)
			if err != nil {
				return nil, err
			}
			qc, err = quic.Dial(ctx, packetConn, &net.UDPAddr{IP: ip, Port: port}, tlsconfig, l.quicconfig)
			if err != nil {
				packetConn.Close()
				return nil, err
			}
		} else {
			qc, err = quic.DialAddr(ctx, hostport, tlsconfig, l.quicconfig)
			if err != nil {
				return nil, err
			}
		}
		qs, err := qc.OpenStreamSync(ctx)
		if err != nil {
			return nil, err
		}
		return &linkQUICStream{
			Conn:       qc,
			Stream:     qs,
			packetConn: packetConn,
		}, nil
	})
}

func (l *linkQUIC) listen(ctx context.Context, url *url.URL, _ string) (net.Listener, error) {
	ql, err := quic.ListenAddr(url.Host, l.tlsconfig, l.quicconfig)
	if err != nil {
		return nil, err
	}
	ch := make(chan *linkQUICStream)
	lql := &linkQUICListener{
		Listener: ql,
		ch:       ch,
	}
	go func() {
		for {
			qc, err := ql.Accept(ctx)
			switch err {
			case context.Canceled, context.DeadlineExceeded:
				ql.Close()
				fallthrough
			case quic.ErrServerClosed:
				return
			case nil:
				go l.waitForStream(ctx, qc, ch)
			}
		}
	}()
	return lql, nil
}

func (l *linkQUIC) waitForStream(ctx context.Context, qc *quic.Conn, ch chan *linkQUICStream) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	qs, err := qc.AcceptStream(ctx)
	if err != nil {
		_ = qc.CloseWithError(1, fmt.Sprintf("stream error: %s", err))
		return
	}
	select {
	case ch <- &linkQUICStream{
		Conn:   qc,
		Stream: qs,
	}:
	case <-ctx.Done():
		_ = qc.CloseWithError(1, "stream not created")
	}
}

// Close also ends the connection and its LinkDialer socket, which nothing else owns (neko).
func (s *linkQUICStream) Close() error {
	err := s.Stream.Close()
	if s.packetConn != nil {
		_ = s.CloseWithError(0, "")
		s.packetConn.Close()
	}
	return err
}
