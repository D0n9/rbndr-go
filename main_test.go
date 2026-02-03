package main

import (
	"encoding/binary"
	"net"
	"testing"
)

// --- Standard DNS tests (custom domain, host/dig compatible) ---

func TestHandleStandardDNS_AlternatesByID(t *testing.T) {
	domainLabels := domainToLabels("rbndr.us")
	for id, wantIP := range map[uint16]string{
		0: "192.168.0.1",
		1: "127.0.0.1",
		2: "192.168.0.1",
		3: "127.0.0.1",
	} {
		q := buildStandardDNSQuery(id, "7f000001", "c0a80001", "rbndr.us")
		resp := handleStandardDNS(q, domainLabels)
		if resp == nil {
			t.Fatalf("id=%d: nil response", id)
		}
		ip := parseStandardDNSResponseA(resp)
		if ip == nil {
			t.Errorf("id=%d: no A record in response", id)
			continue
		}
		if got := net.IP(ip).String(); got != wantIP {
			t.Errorf("id=%d: got IP %s want %s", id, got, wantIP)
		}
	}
}

func TestHandleStandardDNS_CustomDomain(t *testing.T) {
	// Self-host with -domain=rebind.example.com
	domainLabels := domainToLabels("rebind.example.com")
	q := buildStandardDNSQuery(1, "7f000001", "c0a80001", "rebind.example.com")
	resp := handleStandardDNS(q, domainLabels)
	if resp == nil {
		t.Fatal("nil response")
	}
	ip := parseStandardDNSResponseA(resp)
	if ip == nil {
		t.Fatal("no A record")
	}
	if got := net.IP(ip).String(); got != "127.0.0.1" {
		t.Errorf("got IP %s want 127.0.0.1", got)
	}
	// Wrong domain should get NX
	qBad := buildStandardDNSQuery(1, "7f000001", "c0a80001", "other.example.com")
	respBad := handleStandardDNS(qBad, domainLabels)
	if respBad == nil {
		t.Fatal("expected response for wrong domain")
	}
	if parseStandardDNSResponseA(respBad) != nil {
		t.Error("wrong domain should have no A record (NX)")
	}
}

func TestHandleStandardDNS_MatchingLabelsRefused(t *testing.T) {
	domainLabels := domainToLabels("rbndr.us")
	q := buildStandardDNSQuery(1, "7f000001", "7f000001", "rbndr.us")
	resp := handleStandardDNS(q, domainLabels)
	if resp == nil {
		t.Fatal("nil response")
	}
	if parseStandardDNSResponseA(resp) != nil {
		t.Error("matching labels should have no A record (REFUSED)")
	}
}

func TestDomainToLabels(t *testing.T) {
	tests := []struct {
		domain string
		want   []string
	}{
		{"rbndr.us", []string{"rbndr", "us"}},
		{"rebind.example.com", []string{"rebind", "example", "com"}},
		{"  EXAMPLE.COM  ", []string{"example", "com"}},
	}
	for _, tt := range tests {
		got := domainToLabels(tt.domain)
		if len(got) != len(tt.want) {
			t.Errorf("domainToLabels(%q) len=%d want %d", tt.domain, len(got), len(tt.want))
			continue
		}
		for i := range got {
			if got[i] != tt.want[i] {
				t.Errorf("domainToLabels(%q)[%d]=%q want %q", tt.domain, i, got[i], tt.want[i])
			}
		}
	}
}

// --- Legacy 60-byte format tests (handleQuery) ---

// buildQuery builds a 60-byte query packet in the same layout as the C server expects.
// primaryHex and secondaryHex are 8 lowercase hex chars each (e.g. "7f000001", "c0a80001").
func buildQuery(id uint16, primaryHex, secondaryHex string) []byte {
	if len(primaryHex) != 8 || len(secondaryHex) != 8 {
		panic("labels must be 8 chars")
	}
	b := make([]byte, 60)
	binary.BigEndian.PutUint16(b[0:2], id)
	// flags: 0 (query)
	binary.BigEndian.PutUint16(b[4:6], 1) // QDCount = 1
	b[12] = 8
	copy(b[13:21], []byte(primaryHex))
	b[21] = 8
	copy(b[22:30], []byte(secondaryHex))
	// domain: rbndr.us
	b[30] = 5
	copy(b[31:36], []byte("rbndr"))
	b[36] = 2
	copy(b[37:39], []byte("us"))
	b[39] = 0
	binary.BigEndian.PutUint16(b[40:42], 1) // QType A
	binary.BigEndian.PutUint16(b[42:44], 1) // QClass IN
	return b
}

func TestParseIP4Label(t *testing.T) {
	tests := []struct {
		label string
		want  string
		ok    bool
	}{
		{"7f000001", "127.0.0.1", true},
		{"c0a80001", "192.168.0.1", true},
		{"00000000", "0.0.0.0", true},
		{"ffffffff", "255.255.255.255", true},
		{"7F000001", "127.0.0.1", false}, // uppercase invalid per C (lowercase only)
		{"7f00000", "127.0.0.1", false},
		{"7f0000012", "127.0.0.1", false},
		{"gg000001", "", false},
	}
	for _, tt := range tests {
		got, ok := parseIP4Label([]byte(tt.label))
		if ok != tt.ok {
			t.Errorf("parseIP4Label(%q) ok=%v want %v", tt.label, ok, tt.ok)
			continue
		}
		if !tt.ok {
			continue
		}
		ip := net.IP(got).String()
		if ip != tt.want {
			t.Errorf("parseIP4Label(%q) = %s want %s", tt.label, ip, tt.want)
		}
	}
}

func TestHandleQuery_DomainBytesMatch(t *testing.T) {
	q := buildQuery(1, "7f000001", "c0a80001")
	query := &header{}
	if err := query.unmarshal(q); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	reply := &header{}
	reply.Labels = query.Labels
	got := reply.domainBytes()
	if len(got) != len(expectedDomain) {
		t.Fatalf("domainBytes len=%d expectedDomain len=%d", len(got), len(expectedDomain))
	}
	for i := range expectedDomain {
		if got[i] != expectedDomain[i] {
			t.Errorf("at %d: got %d want %d", i, got[i], expectedDomain[i])
		}
	}
}

func TestHandleQuery_LegacyAlternatesByID(t *testing.T) {
	for id, wantIP := range map[uint16]string{
		0: "192.168.0.1",
		1: "127.0.0.1",
		2: "192.168.0.1",
		3: "127.0.0.1",
	} {
		q := buildQuery(id, "7f000001", "c0a80001")
		query := &header{}
		if err := query.unmarshal(q); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}
		resp := handleQuery(query)
		if len(resp) != 60 {
			t.Errorf("id=%d: response len=%d want 60", id, len(resp))
			continue
		}
		ip := net.IP(resp[56:60]).String()
		if ip != wantIP {
			t.Errorf("id=%d: got IP %s want %s", id, ip, wantIP)
		}
	}
}

func TestHandleQuery_InvalidDomain(t *testing.T) {
	b := buildQuery(1, "7f000001", "c0a80001")
	b[31] = 'x' // corrupt domain to "xbndr"
	query := &header{}
	if err := query.unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resp := handleQuery(query)
	if len(resp) != 44 {
		t.Errorf("expected error response 44 bytes, got %d", len(resp))
	}
	// rcode in low nibble of flags (bytes 2-3)
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0xf
	if rcode != nsR_NX {
		t.Errorf("rcode=%d want NXDOMAIN (%d)", rcode, nsR_NX)
	}
}

func TestHandleQuery_MatchingLabelsRefused(t *testing.T) {
	// same label for both -> refused
	b := buildQuery(1, "7f000001", "7f000001")
	query := &header{}
	if err := query.unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resp := handleQuery(query)
	if len(resp) != 44 {
		t.Errorf("expected error response 44 bytes, got %d", len(resp))
	}
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0xf
	if rcode != nsR_REF {
		t.Errorf("rcode=%d want REFUSED (%d)", rcode, nsR_REF)
	}
}

func TestHandleQuery_InvalidHexLabel(t *testing.T) {
	b := buildQuery(1, "gg000001", "c0a80001")
	query := &header{}
	if err := query.unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resp := handleQuery(query)
	if len(resp) != 44 {
		t.Errorf("expected error response 44 bytes, got %d", len(resp))
	}
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0xf
	if rcode != nsR_NX {
		t.Errorf("rcode=%d want NXDOMAIN (%d)", rcode, nsR_NX)
	}
}

func TestHandleQuery_QDCountNotOne(t *testing.T) {
	b := buildQuery(1, "7f000001", "c0a80001")
	binary.BigEndian.PutUint16(b[4:6], 2) // QDCount = 2
	query := &header{}
	if err := query.unmarshal(b); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	resp := handleQuery(query)
	if len(resp) != 44 {
		t.Errorf("expected error response 44 bytes, got %d", len(resp))
	}
	rcode := binary.BigEndian.Uint16(resp[2:4]) & 0xf
	if rcode != nsR_NOI {
		t.Errorf("rcode=%d want NOTIMPL (%d)", rcode, nsR_NOI)
	}
}

func TestMarshalUnmarshalRoundTrip(t *testing.T) {
	q := buildQuery(42, "7f000001", "c0a80001")
	h := &header{}
	if err := h.unmarshal(q); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	full := h.marshal(true)
	if len(full) != 60 {
		t.Fatalf("marshal full len=%d want 60", len(full))
	}
	errOnly := h.marshal(false)
	if len(errOnly) != 44 {
		t.Fatalf("marshal error len=%d want 44", len(errOnly))
	}
	h2 := &header{}
	if err := h2.unmarshal(full); err != nil {
		t.Fatalf("unmarshal full: %v", err)
	}
	if h2.ID != h.ID || h2.QDCount != h.QDCount {
		t.Errorf("roundtrip mismatch")
	}
}
