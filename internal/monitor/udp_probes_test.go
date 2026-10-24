package monitor

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"
)

func TestBuildDNSProbeQueryAsksRootNS(t *testing.T) {
	query, id := buildDNSProbeQuery()
	if len(query) != 17 {
		t.Fatalf("query length = %d, want 17", len(query))
	}
	if got := binary.BigEndian.Uint16(query[0:2]); got != id {
		t.Fatalf("id = %d, want %d", got, id)
	}
	// header: RD flag, one question; question: root name, type NS, class IN
	want := []byte{0x01, 0x00, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 2, 0, 1}
	if !bytes.Equal(query[2:], want) {
		t.Fatalf("query = % x, want % x", query[2:], want)
	}
}

func TestCheckUDPDNSAcceptsAnyResponse(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	go func() {
		buf := make([]byte, 512)
		n, addr, err := server.ReadFromUDP(buf)
		if err != nil {
			return
		}
		resp := append([]byte(nil), buf[:n]...)
		resp[2] |= 0x80 // QR
		resp[3] = 0x05  // REFUSED still proves the server answers
		_, _ = server.WriteToUDP(resp, addr)
	}()

	result := UDPChecker{}.Check(t.Context(), Monitor{ID: 1, Kind: "udp", Target: server.LocalAddr().String(), TLSMode: "dns", Timeout: 2 * time.Second})
	if result.Status != StatusUp {
		t.Fatalf("status = %s (%s), want up", result.Status, result.Message)
	}
}
