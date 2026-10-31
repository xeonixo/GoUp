package monitor

import (
	"bytes"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	mdns "github.com/miekg/dns"
)

// dohSession performs RFC 8484 DNS over HTTPS.
// POST sends the DNS wire bytes as application/dns-message.
// GET sends the same bytes, base64url without padding, in the dns parameter.
// The endpoint path is used unchanged, so /dns-query/<client-id> stays intact.
type dohSession struct {
	client   *http.Client
	endpoint string
	method   SDNSMethod
	sni      string
	timeout  time.Duration
	closeFn  func()
	status   *int
	tlsState *tls.ConnectionState
}

func openDoHSession(ctx context.Context, target SDNSTarget, settings sdnsSettings, network string, timeout time.Duration) (sdnsSession, error) {
	host := SDNSEndpointHost(SDNSTransportDoH, target.Endpoint)
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.DisableCompression = true
	transport.ForceAttemptHTTP2 = true
	transport.TLSHandshakeTimeout = timeout
	transport.ResponseHeaderTimeout = timeout
	transport.TLSClientConfig = sdnsTLSConfig(host, target.SNI, settings.Verify, []string{"h2", "http/1.1"})
	dialer := newMonitorDialer(timeout)
	transport.DialContext = func(dialCtx context.Context, dialNetwork, addr string) (net.Conn, error) {
		if network != "" {
			dialNetwork = network
		}
		return dialer.DialContext(dialCtx, dialNetwork, addr)
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
		closeFn:  transport.CloseIdleConnections,
	}, nil
}

func (s *dohSession) Exchange(ctx context.Context, query *mdns.Msg) (*mdns.Msg, error) {
	wire, err := query.Pack()
	if err != nil {
		return nil, err
	}
	req, err := s.newRequest(ctx, wire)
	if err != nil {
		return nil, err
	}
	resp, err := s.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	code := resp.StatusCode
	s.status = &code
	if resp.TLS != nil {
		state := *resp.TLS
		s.tlsState = &state
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, sdnsMaxMessageBytes+1))
	if err != nil {
		return nil, err
	}
	if len(body) > sdnsMaxMessageBytes {
		return nil, fmt.Errorf("dns response exceeds %d bytes", sdnsMaxMessageBytes)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	if !isDNSMessageType(resp.Header.Get("Content-Type")) {
		return nil, fmt.Errorf("unexpected content type %q", resp.Header.Get("Content-Type"))
	}
	return unpackSDNSResponse(body, query.Id)
}

func (s *dohSession) newRequest(ctx context.Context, wire []byte) (*http.Request, error) {
	method := http.MethodPost
	var body io.Reader
	endpoint := s.endpoint
	if s.method == SDNSMethodGET {
		method = http.MethodGet
		parsed, err := url.Parse(s.endpoint)
		if err != nil {
			return nil, err
		}
		query := parsed.Query()
		query.Set("dns", encodeDoHParameter(wire))
		parsed.RawQuery = query.Encode()
		endpoint = parsed.String()
	} else {
		body = bytes.NewReader(wire)
	}

	req, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", dnsMessageMediaType)
	req.Header.Set("Accept-Encoding", "identity")
	req.Header.Set("Cache-Control", "no-cache")
	if s.method != SDNSMethodGET {
		req.Header.Set("Content-Type", dnsMessageMediaType)
		req.ContentLength = int64(len(wire))
		copied := append([]byte(nil), wire...)
		req.GetBody = func() (io.ReadCloser, error) {
			return io.NopCloser(bytes.NewReader(copied)), nil
		}
	}
	applySDNSHostHeader(req, s.sni)
	return req, nil
}

func (s *dohSession) HTTPStatus() *int { return s.status }

func (s *dohSession) TLS() *tls.ConnectionState { return s.tlsState }

func (s *dohSession) Close() {
	if s.closeFn != nil {
		s.closeFn()
	}
}

func isDNSMessageType(header string) bool {
	header = strings.TrimSpace(header)
	if header == "" {
		return true
	}
	media, _, err := mime.ParseMediaType(header)
	if err != nil {
		return false
	}
	return strings.EqualFold(media, dnsMessageMediaType)
}

// applySDNSHostHeader sends the TLS server name as the HTTP Host when the URL
// dials an IP. Resolvers that certificate-pin a hostname expect that Host.
func applySDNSHostHeader(req *http.Request, sni string) {
	if req == nil || req.URL == nil {
		return
	}
	sni = strings.TrimSpace(sni)
	host := req.URL.Hostname()
	if sni == "" || net.ParseIP(host) == nil || net.ParseIP(sni) != nil {
		return
	}
	port := req.URL.Port()
	if port == "" || port == "443" {
		req.Host = sni
		return
	}
	req.Host = net.JoinHostPort(sni, port)
}
