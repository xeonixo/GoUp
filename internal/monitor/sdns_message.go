package monitor

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"

	mdns "github.com/miekg/dns"
)

const (
	dnsMessageMediaType = "application/dns-message"
	sdnsMaxMessageBytes = 65535
)

// buildSDNSQuery builds one recursive DNS question.
// DoH and DoH3 use id 0, which is the RFC 8484 recommendation and matches
// the dns= query parameter operators paste from curl. DoT and DoQ use a
// non-zero id so two queries on one connection (A and AAAA) stay distinct.
func buildSDNSQuery(name string, qtype uint16, id uint16) (*mdns.Msg, error) {
	fqdn := mdns.Fqdn(strings.TrimSpace(name))
	if _, ok := mdns.IsDomainName(fqdn); fqdn == "." || !ok {
		return nil, fmt.Errorf("invalid dns name %q", name)
	}
	msg := new(mdns.Msg)
	msg.SetQuestion(fqdn, qtype)
	msg.RecursionDesired = true
	msg.Id = id
	return msg, nil
}

func sdnsQueryID(transport SDNSTransport, qtype uint16) uint16 {
	if transport.UsesHTTP() {
		return 0
	}
	if qtype == 0 {
		return 1
	}
	return qtype
}

// encodeDoHParameter is the RFC 8484 dns query value: base64url, no padding.
func encodeDoHParameter(wire []byte) string {
	return base64.RawURLEncoding.EncodeToString(wire)
}

func writeDNSFrame(w io.Writer, raw []byte) error {
	if len(raw) == 0 || len(raw) > sdnsMaxMessageBytes {
		return fmt.Errorf("dns message has invalid length %d", len(raw))
	}
	frame := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(frame[:2], uint16(len(raw)))
	copy(frame[2:], raw)
	_, err := w.Write(frame)
	return err
}

func readDNSFrame(r io.Reader) ([]byte, error) {
	var hdr [2]byte
	if _, err := io.ReadFull(r, hdr[:]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(hdr[:]))
	if n == 0 || n > sdnsMaxMessageBytes {
		return nil, fmt.Errorf("dns message has invalid length %d", n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

func unpackSDNSResponse(raw []byte, queryID uint16) (*mdns.Msg, error) {
	msg := new(mdns.Msg)
	if err := msg.Unpack(raw); err != nil {
		return nil, fmt.Errorf("dns response unpack failed: %w", err)
	}
	if queryID != 0 && msg.Id != queryID {
		return nil, fmt.Errorf("dns response id mismatch")
	}
	return msg, nil
}

func sdnsQtypes(recordType DNSRecordType) []uint16 {
	switch NormalizeDNSRecordType(string(recordType)) {
	case DNSRecordTypeA:
		return []uint16{mdns.TypeA}
	case DNSRecordTypeAAAA:
		return []uint16{mdns.TypeAAAA}
	case DNSRecordTypeCNAME:
		return []uint16{mdns.TypeCNAME}
	case DNSRecordTypeMX:
		return []uint16{mdns.TypeMX}
	case DNSRecordTypeTXT:
		return []uint16{mdns.TypeTXT}
	case DNSRecordTypeNS:
		return []uint16{mdns.TypeNS}
	case DNSRecordTypeSRV:
		return []uint16{mdns.TypeSRV}
	case DNSRecordTypeCAA:
		return []uint16{mdns.TypeCAA}
	case DNSRecordTypeSOA:
		return []uint16{mdns.TypeSOA}
	default:
		return []uint16{mdns.TypeA, mdns.TypeAAAA}
	}
}

func interpretSDNSResponse(msg *mdns.Msg, qtype uint16) ([]string, error) {
	if msg == nil {
		return nil, fmt.Errorf("empty dns response")
	}
	if msg.Truncated {
		return nil, fmt.Errorf("truncated dns response")
	}
	if msg.Rcode == mdns.RcodeNameError {
		return nil, fmt.Errorf("NXDOMAIN")
	}
	if msg.Rcode != mdns.RcodeSuccess {
		label := mdns.RcodeToString[msg.Rcode]
		if label == "" {
			label = fmt.Sprintf("%d", msg.Rcode)
		}
		return nil, fmt.Errorf("dns rcode %s", label)
	}
	return formatSDNSAnswers(msg.Answer, qtype), nil
}

func formatSDNSAnswers(records []mdns.RR, qtype uint16) []string {
	results := make([]string, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for _, record := range records {
		if record == nil || record.Header() == nil || record.Header().Rrtype != qtype {
			continue
		}
		formatted := formatSDNSRR(record)
		if formatted == "" {
			continue
		}
		if _, ok := seen[formatted]; ok {
			continue
		}
		seen[formatted] = struct{}{}
		results = append(results, formatted)
	}
	sort.Strings(results)
	return results
}

func formatSDNSRR(record mdns.RR) string {
	switch rr := record.(type) {
	case *mdns.A:
		if rr.A == nil {
			return ""
		}
		return rr.A.String()
	case *mdns.AAAA:
		if rr.AAAA == nil {
			return ""
		}
		return rr.AAAA.String()
	case *mdns.CNAME:
		return trimSDNSName(rr.Target)
	case *mdns.MX:
		host := trimSDNSName(rr.Mx)
		if host == "" {
			return ""
		}
		return fmt.Sprintf("%d %s", rr.Preference, host)
	case *mdns.TXT:
		return strings.Join(rr.Txt, "")
	case *mdns.NS:
		return trimSDNSName(rr.Ns)
	case *mdns.SRV:
		target := trimSDNSName(rr.Target)
		if target == "" {
			return ""
		}
		return fmt.Sprintf("%d %d %d %s", rr.Priority, rr.Weight, rr.Port, target)
	case *mdns.CAA:
		return fmt.Sprintf("%d %s %s", rr.Flag, strings.TrimSpace(rr.Tag), strings.TrimSpace(rr.Value))
	case *mdns.SOA:
		ns := trimSDNSName(rr.Ns)
		mbox := trimSDNSName(rr.Mbox)
		return fmt.Sprintf("%s %s %d %d %d %d %d", ns, mbox, rr.Serial, rr.Refresh, rr.Retry, rr.Expire, rr.Minttl)
	default:
		return ""
	}
}

func trimSDNSName(name string) string {
	return strings.TrimSpace(strings.TrimSuffix(name, "."))
}

func sdnsRecordTypeName(qtype uint16) string {
	switch qtype {
	case mdns.TypeA:
		return "A"
	case mdns.TypeAAAA:
		return "AAAA"
	case mdns.TypeCNAME:
		return "CNAME"
	case mdns.TypeMX:
		return "MX"
	case mdns.TypeTXT:
		return "TXT"
	case mdns.TypeNS:
		return "NS"
	case mdns.TypeSRV:
		return "SRV"
	case mdns.TypeCAA:
		return "CAA"
	case mdns.TypeSOA:
		return "SOA"
	default:
		return "DNS"
	}
}

// sdnsDialNetwork selects tcp/udp and the IP family, matching the HTTPS checker:
// a literal address uses its own family, and a requested family that disagrees is an error.
func sdnsDialNetwork(host string, family TCPAddressFamily, udp bool) (string, error) {
	v4, v6, any := "tcp4", "tcp6", "tcp"
	if udp {
		v4, v6, any = "udp4", "udp6", "udp"
	}
	family = NormalizeTCPAddressFamily(string(family))
	ip := net.ParseIP(strings.Trim(strings.TrimSpace(host), "[]"))
	if ip != nil {
		if ip.To4() != nil {
			if family == TCPAddressFamilyIPv6 {
				return "", fmt.Errorf("ip family is IPv6 but resolver is IPv4")
			}
			return v4, nil
		}
		if family == TCPAddressFamilyIPv4 {
			return "", fmt.Errorf("ip family is IPv4 but resolver is IPv6")
		}
		return v6, nil
	}
	switch family {
	case TCPAddressFamilyIPv4:
		return v4, nil
	case TCPAddressFamilyIPv6:
		return v6, nil
	default:
		return any, nil
	}
}
