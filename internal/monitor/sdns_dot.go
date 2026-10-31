package monitor

import (
	"context"
	"crypto/tls"
	"net"
	"time"

	mdns "github.com/miekg/dns"
)

// dotSession is a DNS over TLS connection (RFC 7858): a 2-byte length prefix
// in front of each DNS message, ALPN "dot", default port 853.
type dotSession struct {
	conn    net.Conn
	state   tls.ConnectionState
	hasTLS  bool
	timeout time.Duration
}

func openDoTSession(ctx context.Context, target SDNSTarget, settings sdnsSettings, network string, timeout time.Duration) (sdnsSession, error) {
	host := SDNSEndpointHost(SDNSTransportDoT, target.Endpoint)
	dialer := &tls.Dialer{
		NetDialer: newMonitorDialer(timeout),
		Config:    sdnsTLSConfig(host, target.SNI, settings.Verify, []string{"dot"}),
	}
	conn, err := dialer.DialContext(ctx, network, target.Endpoint)
	if err != nil {
		return nil, err
	}
	session := &dotSession{conn: conn, timeout: timeout}
	if tlsConn, ok := conn.(*tls.Conn); ok {
		session.state = tlsConn.ConnectionState()
		session.hasTLS = true
	}
	return session, nil
}

func (s *dotSession) Exchange(ctx context.Context, query *mdns.Msg) (*mdns.Msg, error) {
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	_ = s.conn.SetDeadline(deadlineFromContext(ctx, s.timeout))
	if err := writeDNSFrame(s.conn, wire); err != nil {
		return nil, err
	}
	raw, err := readDNSFrame(s.conn)
	if err != nil {
		return nil, err
	}
	return unpackSDNSResponse(raw, query.Id)
}

func (s *dotSession) HTTPStatus() *int { return nil }

func (s *dotSession) TLS() *tls.ConnectionState {
	if !s.hasTLS {
		return nil
	}
	return &s.state
}

func (s *dotSession) Close() {
	if s.conn != nil {
		_ = s.conn.Close()
	}
}

func deadlineFromContext(ctx context.Context, fallback time.Duration) time.Time {
	if deadline, ok := ctx.Deadline(); ok {
		return deadline
	}
	if fallback <= 0 {
		fallback = 10 * time.Second
	}
	return time.Now().Add(fallback)
}
