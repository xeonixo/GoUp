package monitor

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

// doqSession is DNS over QUIC (RFC 9250): one bidirectional stream per query,
// the same 2-byte length prefix as DNS over TLS, ALPN "doq".
type doqSession struct {
	conn    *quic.Conn
	pc      net.PacketConn
	state   tls.ConnectionState
	hasTLS  bool
	timeout time.Duration
}

func openDoQSession(ctx context.Context, target SDNSTarget, settings sdnsSettings, network string, timeout time.Duration) (sdnsSession, error) {
	host, port, err := splitSDNSHostPort(target.Endpoint, "853")
	if err != nil {
		return nil, err
	}
	conn, pc, state, err := dialSDNSQUIC(ctx, network, host, port, target.SNI, settings.Verify, []string{"doq"}, timeout)
	if err != nil {
		return nil, err
	}
	return &doqSession{conn: conn, pc: pc, state: state, hasTLS: true, timeout: timeout}, nil
}

func (s *doqSession) Exchange(ctx context.Context, query *mdns.Msg) (*mdns.Msg, error) {
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	stream, err := s.conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	defer stream.CancelRead(quic.StreamErrorCode(0))
	_ = stream.SetDeadline(deadlineFromContext(ctx, s.timeout))
	if err := writeDNSFrame(stream, wire); err != nil {
		return nil, err
	}
	// The client finishes the send side after the query (RFC 9250).
	if err := stream.Close(); err != nil {
		return nil, err
	}
	raw, err := readDNSFrame(stream)
	if err != nil {
		return nil, err
	}
	return unpackSDNSResponse(raw, query.Id)
}

func (s *doqSession) HTTPStatus() *int { return nil }

func (s *doqSession) TLS() *tls.ConnectionState {
	if !s.hasTLS {
		return nil
	}
	return &s.state
}

func (s *doqSession) Close() {
	if s.conn != nil {
		_ = s.conn.CloseWithError(quic.ApplicationErrorCode(0), "")
	}
	if s.pc != nil {
		_ = s.pc.Close()
	}
}

func openDoH3Session(ctx context.Context, target SDNSTarget, settings sdnsSettings, network string, timeout time.Duration) (sdnsSession, error) {
	host := SDNSEndpointHost(SDNSTransportDoH3, target.Endpoint)
	transport := &http3.Transport{
		TLSClientConfig: sdnsTLSConfig(host, target.SNI, settings.Verify, []string{http3.NextProtoH3}),
		QUICConfig: &quic.Config{
			HandshakeIdleTimeout: timeout,
			MaxIdleTimeout:       timeout,
		},
		Dial: func(dialCtx context.Context, addr string, tlsCfg *tls.Config, _ *quic.Config) (*quic.Conn, error) {
			dialHost, dialPort, err := splitSDNSHostPort(addr, "443")
			if err != nil {
				return nil, err
			}
			// Keep the ALPN http3 already put on tlsCfg ("h3") and apply our
			// certificate policy (hostname SNI, or IP SAN when the URL is an address).
			next := append([]string(nil), tlsCfg.NextProtos...)
			conn, pc, _, err := dialSDNSQUIC(dialCtx, network, dialHost, dialPort, target.SNI, settings.Verify, next, timeout)
			if err != nil {
				return nil, err
			}
			go func() {
				<-conn.Context().Done()
				_ = pc.Close()
			}()
			return conn, nil
		},
	}
	client := &http.Client{
		Timeout:   timeout,
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return fmt.Errorf("redirects are not allowed")
		},
	}
	return &dohSession{
		client:   client,
		endpoint: target.Endpoint,
		method:   settings.Method,
		sni:      target.SNI,
		timeout:  timeout,
		closeFn: func() {
			_ = transport.Close()
		},
	}, nil
}

func dialSDNSQUIC(ctx context.Context, network, host, port, sni string, verify bool, nextProtos []string, timeout time.Duration) (*quic.Conn, net.PacketConn, tls.ConnectionState, error) {
	ips, err := resolveSDNS(ctx, host, network)
	if err != nil {
		return nil, nil, tls.ConnectionState{}, err
	}
	portNumber, err := strconv.Atoi(port)
	if err != nil || portNumber <= 0 || portNumber > 65535 {
		return nil, nil, tls.ConnectionState{}, fmt.Errorf("invalid resolver port")
	}
	tlsConf := sdnsTLSConfig(host, sni, verify, nextProtos)
	quicConf := &quic.Config{
		HandshakeIdleTimeout: timeout,
		MaxIdleTimeout:       timeout,
	}

	var lastErr error
	limit := len(ips)
	if limit > 3 {
		limit = 3
	}
	for _, ip := range ips[:limit] {
		if ctx.Err() != nil {
			return nil, nil, tls.ConnectionState{}, ctx.Err()
		}
		conn, pc, state, dialErr := dialQUICIP(ctx, network, ip, portNumber, tlsConf, quicConf)
		if dialErr != nil {
			lastErr = dialErr
			continue
		}
		return conn, pc, state, nil
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("no address for %s", host)
	}
	return nil, nil, tls.ConnectionState{}, lastErr
}

func dialQUICIP(ctx context.Context, network string, ip net.IP, port int, tlsConf *tls.Config, quicConf *quic.Config) (*quic.Conn, net.PacketConn, tls.ConnectionState, error) {
	listenNetwork := network
	var bind net.IP
	switch network {
	case "udp4":
		bind = net.IPv4zero
	case "udp6":
		bind = net.IPv6unspecified
	default:
		if ip.To4() != nil {
			listenNetwork = "udp4"
			bind = net.IPv4zero
		} else {
			listenNetwork = "udp6"
			bind = net.IPv6unspecified
		}
	}
	pc, err := net.ListenUDP(listenNetwork, &net.UDPAddr{IP: bind, Port: 0})
	if err != nil {
		return nil, nil, tls.ConnectionState{}, err
	}
	remote := &net.UDPAddr{IP: ip, Port: port}
	conn, err := quic.Dial(ctx, pc, remote, tlsConf, quicConf)
	if err != nil {
		_ = pc.Close()
		return nil, nil, tls.ConnectionState{}, err
	}
	return conn, pc, conn.ConnectionState().TLS, nil
}

func resolveSDNS(ctx context.Context, host, network string) ([]net.IP, error) {
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if ip := net.ParseIP(host); ip != nil {
		if !monitorAllowsIP(ip) {
			return nil, fmt.Errorf("target address is blocked")
		}
		return []net.IP{ip}, nil
	}
	lookup := "ip"
	switch network {
	case "udp4", "tcp4":
		lookup = "ip4"
	case "udp6", "tcp6":
		lookup = "ip6"
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, lookup, host)
	if err != nil {
		return nil, err
	}
	allowed := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if monitorAllowsIP(ip) {
			allowed = append(allowed, ip)
		}
	}
	if len(allowed) == 0 {
		return nil, fmt.Errorf("target address is blocked")
	}
	return allowed, nil
}

func splitSDNSHostPort(raw, defaultPort string) (string, string, error) {
	host, port, err := splitOptionalHostPort(stripSDNSScheme(raw), defaultPort)
	if err != nil {
		return "", "", err
	}
	host = strings.Trim(strings.TrimSpace(host), "[]")
	if host == "" {
		return "", "", fmt.Errorf("resolver is missing a host")
	}
	if _, err := normalizeSDNSPort(port); err != nil {
		return "", "", err
	}
	return host, port, nil
}
