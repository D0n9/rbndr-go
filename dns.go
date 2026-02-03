// Package main: standard DNS packet parsing and building for rebinding.
// Supports configurable domain suffix so you can self-host with any domain.

package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"strings"
)

// Standard DNS constants.
const (
	dnsTypeA  = 1
	dnsClassIN = 1
	dnsCompressPointer = 0xc0
)

// parseQNAME parses DNS QNAME from b starting at off, returns labels and new offset after QNAME (after final 0).
func parseQNAME(b []byte, off int) (labels [][]byte, end int, err error) {
	labels = nil
	for off < len(b) {
		l := int(b[off])
		off++
		if l == 0 {
			return labels, off, nil
		}
		if l&dnsCompressPointer == dnsCompressPointer {
			// Compressed name: 2 byte pointer
			if off+1 > len(b) {
				return nil, 0, fmt.Errorf("compressed name truncated")
			}
			ptr := int(b[off-1]&0x3f)<<8 | int(b[off])
			off++
			if ptr >= off-2 {
				return nil, 0, fmt.Errorf("invalid compression pointer")
			}
			// Resolve pointer (no nested compression in our parser for simplicity)
			rest, _, err := parseQNAME(b, ptr)
			if err != nil {
				return nil, 0, err
			}
			return append(labels, rest...), off, nil
		}
		if off+l > len(b) {
			return nil, 0, fmt.Errorf("label truncated")
		}
		labels = append(labels, append([]byte(nil), b[off:off+l]...))
		off += l
	}
	return nil, 0, fmt.Errorf("qname overflow")
}

// parseStandardDNSRequest parses a standard DNS query. Returns id, question section (for echo), labels, qtype, qclass, questionEndOffset, error.
func parseStandardDNSRequest(b []byte) (id uint16, question []byte, labels [][]byte, qtype, qclass uint16, questionEnd int, err error) {
	if len(b) < 12 {
		return 0, nil, nil, 0, 0, 0, fmt.Errorf("packet too short")
	}
	id = binary.BigEndian.Uint16(b[0:2])
	qdcount := binary.BigEndian.Uint16(b[4:6])
	if qdcount != 1 {
		return id, nil, nil, 0, 0, 0, fmt.Errorf("qdcount != 1")
	}
	labels, end, err := parseQNAME(b, 12)
	if err != nil {
		return 0, nil, nil, 0, 0, 0, err
	}
	if end+4 > len(b) {
		return 0, nil, nil, 0, 0, 0, fmt.Errorf("question truncated")
	}
	qtype = binary.BigEndian.Uint16(b[end : end+2])
	qclass = binary.BigEndian.Uint16(b[end+2 : end+4])
	questionEnd = end + 4
	question = append([]byte(nil), b[12:questionEnd]...)
	return id, question, labels, qtype, qclass, questionEnd, nil
}

// labelsMatchSuffix returns true if name labels end with domain labels (case-insensitive).
func labelsMatchSuffix(nameLabels [][]byte, domainLabels []string) bool {
	if len(nameLabels) < len(domainLabels) {
		return false
	}
	start := len(nameLabels) - len(domainLabels)
	for i, dl := range domainLabels {
		if !bytes.EqualFold(nameLabels[start+i], []byte(dl)) {
			return false
		}
	}
	return true
}

// handleStandardDNS handles a standard DNS query packet and returns the response.
// domainLabels is the allowed suffix (e.g. ["rbndr","us"] for rbndr.us), lowercased.
func handleStandardDNS(raw []byte, domainLabels []string) []byte {
	id, question, labels, qtype, _, _, err := parseStandardDNSRequest(raw)
	if err != nil {
		return nil
	}
	// Need at least 2 hex labels + domain suffix
	if len(labels) < 2+len(domainLabels) {
		return buildStandardDNSResponse(id, question, 0, nsR_NX, nil)
	}
	primary := labels[0]
	secondary := labels[1]
	suffix := labels[2:]
	if !labelsMatchSuffix(suffix, domainLabels) {
		return buildStandardDNSResponse(id, question, 0, nsR_NX, nil)
	}
	if len(primary) != 8 || len(secondary) != 8 {
		return buildStandardDNSResponse(id, question, 0, nsR_NX, nil)
	}
	if bytes.EqualFold(primary, secondary) {
		return buildStandardDNSResponse(id, question, 0, nsR_REF, nil)
	}
	if qtype != dnsTypeA {
		return buildStandardDNSResponse(id, question, 0, nsR_OK, nil) // no answer, rcode 0
	}
	// Pick IP by ID (odd -> primary, even -> secondary)
	var chosen []byte
	if (id & 1) != 0 {
		chosen = primary
	} else {
		chosen = secondary
	}
	ip4, ok := parseIP4Label(chosen)
	if !ok {
		return buildStandardDNSResponse(id, question, 0, nsR_NX, nil)
	}
	return buildStandardDNSResponse(id, question, 1, nsR_OK, ip4)
}

// buildStandardDNSResponse builds a standard DNS response.
// question is the raw question section (QNAME + QTYPE + QCLASS, 12 bytes offset in request).
// ancount is 0 or 1, rcode is response code, ip4 is the A record data if ancount==1.
func buildStandardDNSResponse(id uint16, question []byte, ancount uint16, rcode uint16, ip4 []byte) []byte {
	// Header: 12 bytes
	flags := uint16(1<<15 | 1<<10) | (rcode & 0xf) // QR=1, AA=1, RCODE
	header := make([]byte, 12)
	binary.BigEndian.PutUint16(header[0:2], id)
	binary.BigEndian.PutUint16(header[2:4], flags)
	binary.BigEndian.PutUint16(header[4:6], 1)   // QDCOUNT
	binary.BigEndian.PutUint16(header[6:8], ancount)
	binary.BigEndian.PutUint16(header[8:10], 0)
	binary.BigEndian.PutUint16(header[10:12], 0)
	var out []byte
	out = append(out, header...)
	out = append(out, question...)
	if ancount == 1 && len(ip4) == 4 {
		// Answer: NAME (pointer to 12 = 0xc0 0x0c), TYPE, CLASS, TTL, RDLENGTH, RDATA
		out = append(out, 0xc0, 0x0c)
		t := make([]byte, 2)
		binary.BigEndian.PutUint16(t, dnsTypeA)
		out = append(out, t...)
		binary.BigEndian.PutUint16(t, dnsClassIN)
		out = append(out, t...)
		ttl := make([]byte, 4)
		binary.BigEndian.PutUint32(ttl, 1)
		out = append(out, ttl...)
		rdlen := make([]byte, 2)
		binary.BigEndian.PutUint16(rdlen, 4)
		out = append(out, rdlen...)
		out = append(out, ip4...)
	}
	return out
}

// domainToLabels splits "example.com" into ["example", "com"], lowercased and trimmed.
func domainToLabels(domain string) []string {
	domain = strings.TrimSpace(strings.Trim(strings.ToLower(domain), "."))
	if domain == "" {
		return nil
	}
	parts := strings.Split(domain, ".")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// BuildStandardDNSQuery builds a standard DNS query packet for testing.
// Format: <primaryHex>.<secondaryHex>.<domain>
func buildStandardDNSQuery(id uint16, primaryHex, secondaryHex, domain string) []byte {
	labels := domainToLabels(domain)
	if len(primaryHex) != 8 || len(secondaryHex) != 8 {
		panic("hex labels must be 8 chars")
	}
	// QNAME: 8 "7f000001" 8 "c0a80001" then domain labels then 0
	var qname []byte
	qname = append(qname, 8)
	qname = append(qname, []byte(primaryHex)...)
	qname = append(qname, 8)
	qname = append(qname, []byte(secondaryHex)...)
	for _, l := range labels {
		qname = append(qname, byte(len(l)))
		qname = append(qname, []byte(l)...)
	}
	qname = append(qname, 0)
	// Header: 12 bytes
	b := make([]byte, 12)
	binary.BigEndian.PutUint16(b[0:2], id)
	// b[2:4] flags = 0
	binary.BigEndian.PutUint16(b[4:6], 1) // QDCOUNT
	// ANCOUNT NSCOUNT ARCOUNT = 0
	b = append(b, qname...)
	t := make([]byte, 4)
	binary.BigEndian.PutUint16(t, dnsTypeA)
	binary.BigEndian.PutUint16(t[2:4], dnsClassIN)
	b = append(b, t...)
	return b
}

// parseStandardDNSResponseA extracts the first A record IP from a standard DNS response, or nil.
func parseStandardDNSResponseA(resp []byte) []byte {
	if len(resp) < 12 {
		return nil
	}
	ancount := binary.BigEndian.Uint16(resp[6:8])
	if ancount == 0 {
		return nil
	}
	// Skip header (12) + question (variable)
	qoff := 12
	for qoff < len(resp) {
		l := int(resp[qoff])
		qoff++
		if l == 0 {
			break
		}
		if l&dnsCompressPointer == dnsCompressPointer {
			qoff++
			break
		}
		if qoff+l > len(resp) {
			return nil
		}
		qoff += l
	}
	qoff += 4 // QTYPE, QCLASS
	if qoff+2+2+4+2 > len(resp) {
		return nil
	}
	// Answer: NAME (2 if pointer)
	if resp[qoff]&dnsCompressPointer == dnsCompressPointer {
		qoff += 2
	}
	if qoff+2+2+4+2+4 > len(resp) {
		return nil
	}
	qoff += 2 + 2 + 4 // TYPE, CLASS, TTL
	rdlen := binary.BigEndian.Uint16(resp[qoff : qoff+2])
	qoff += 2
	if rdlen != 4 || qoff+4 > len(resp) {
		return nil
	}
	return resp[qoff : qoff+4]
}
