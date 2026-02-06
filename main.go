// Package main implements a minimal DNS rebinding nameserver.
// Hostname format: <ipv4-hex>.<ipv4-hex>.<domain>
// Use -domain to set your own suffix (e.g. -domain=rebind.example.com) so you can
// self-host and use custom domains; default is rbndr.us.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"
)

const (
	nsT_A         = 1
	nsC_IN        = 1
	nsR_OK        = 0
	nsR_NX        = 3
	nsR_REF       = 5
	nsR_NOI       = 4
	nsCMPRSFLGS   = 0xc0
	defaultDomain = "rbndr.us"
)

var expectedDomain = []byte{
	5, 'r', 'b', 'n', 'd', 'r',
	2, 'u', 's',
	0,
}

// Packet layout must match C struct for compatibility with standard resolvers.
type qname struct {
	Len   uint8
	Label [8]byte
}

type domainLabel struct {
	Len  uint8
	Data [5]byte
}

type tldLabel struct {
	Len  uint8
	Data [2]byte
}

type root struct {
	Domain domainLabel
	TLD    tldLabel
	Root   uint8
}

type header struct {
	ID      uint16
	Flags   uint16
	QDCount uint16
	ANCount uint16
	NSCount uint16
	ARCount uint16
	Labels  struct {
		Primary   qname
		Secondary qname
		Domain    root
	}
	QType    uint16
	QClass   uint16
	PtrFlag  uint8
	PtrOff   uint8
	Type     uint16
	Class    uint16
	TTL      uint32
	RDLength uint16
	RData    [4]byte // IPv4
}

func (h *header) setQR()            { h.Flags |= 1 << 15 }
func (h *header) setAA()            { h.Flags |= 1 << 10 }
func (h *header) setRCode(c uint16) { h.Flags = (h.Flags & 0xfff0) | (c & 0xf) }
func (h *header) rcode() uint16     { return h.Flags & 0xf }

func parseIP4Label(label []byte) ([]byte, bool) {
	if len(label) != 8 {
		return nil, false
	}
	for _, c := range label {
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f':
			continue
		default:
			return nil, false
		}
	}
	// Parse 8 hex digits as IPv4 (big-endian uint32)
	var u32 uint32
	for i := 0; i < 8; i++ {
		var nibble uint32
		c := label[i]
		if c >= '0' && c <= '9' {
			nibble = uint32(c - '0')
		} else {
			nibble = uint32(c-'a') + 10
		}
		u32 = u32<<4 | nibble
	}
	ip4 := make([]byte, 4)
	binary.BigEndian.PutUint32(ip4, u32)
	return ip4, true
}

// ip4ToHexLabel converts an IPv4 address to the 8-char hex label used in rebinding hostnames.
func ip4ToHexLabel(ip net.IP) (string, bool) {
	ip4 := ip.To4()
	if ip4 == nil {
		return "", false
	}
	return fmt.Sprintf("%02x%02x%02x%02x", ip4[0], ip4[1], ip4[2], ip4[3]), true
}

// rebindHostname generates a rebinding hostname for two IPv4 addresses and the given domain suffix.
func rebindHostname(ip1Str, ip2Str, domain string) (string, error) {
	ip1 := net.ParseIP(strings.TrimSpace(ip1Str))
	ip2 := net.ParseIP(strings.TrimSpace(ip2Str))
	if ip1 == nil || ip2 == nil {
		return "", fmt.Errorf("invalid IP address")
	}
	hex1, ok1 := ip4ToHexLabel(ip1)
	hex2, ok2 := ip4ToHexLabel(ip2)
	if !ok1 || !ok2 {
		return "", fmt.Errorf("both addresses must be IPv4")
	}
	domain = strings.Trim(strings.TrimSpace(domain), ".")
	if domain == "" {
		domain = defaultDomain
	}
	return hex1 + "." + hex2 + "." + domain, nil
}

func runServer(conn *net.UDPConn, domainLabels []string) error {
	buf := make([]byte, 1024)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			log.Printf("error receiving query: %v", err)
			continue
		}
		if n < 12 {
			continue
		}
		// Prefer standard DNS (works with host/dig/browsers and any -domain).
		resp := handleStandardDNS(buf[:n], domainLabels)
		if resp != nil {
			log.Printf("%s\t%s", addr.IP, time.Now().Format(time.ANSIC))
			if _, err := conn.WriteToUDP(resp, addr); err != nil {
				log.Printf("sendto failed: %v", err)
			}
			continue
		}
		// Fallback: legacy 60-byte fixed layout (e.g. old clients), only if domain is default.
		if n >= 44 && len(domainLabels) == 2 && domainLabels[0] == "rbndr" && domainLabels[1] == "us" {
			query := &header{}
			if err := query.unmarshal(buf[:n]); err == nil {
				resp := handleQuery(query)
				if len(resp) > 0 {
					log.Printf("%s\t%s", addr.IP, time.Now().Format(time.ANSIC))
					if _, err := conn.WriteToUDP(resp, addr); err != nil {
						log.Printf("sendto failed: %v", err)
					}
				}
			}
		}
	}
}

// handleQuery builds a response packet for the given query (same logic as C server).
func handleQuery(query *header) []byte {
	reply := &header{}
	reply.ID = query.ID
	reply.QDCount = query.QDCount
	reply.Labels = query.Labels
	reply.QType = query.QType
	reply.QClass = query.QClass
	reply.setQR()
	reply.setAA()
	reply.PtrFlag = nsCMPRSFLGS
	reply.PtrOff = 12
	reply.Type = nsT_A
	reply.Class = nsC_IN
	reply.TTL = 1
	reply.RDLength = 4
	reply.ANCount = query.QDCount

	valid := true
	if query.QDCount != 1 {
		reply.setRCode(nsR_NOI)
		valid = false
	} else if query.Labels.Primary.Len != 8 {
		reply.setRCode(nsR_NX)
		valid = false
	} else if query.Labels.Secondary.Len != 8 {
		reply.setRCode(nsR_NX)
		valid = false
	} else if equalBytes(query.Labels.Primary.Label[:], query.Labels.Secondary.Label[:]) {
		reply.setRCode(nsR_REF)
		valid = false
	} else if !equalBytes(reply.domainBytes(), expectedDomain) {
		reply.setRCode(nsR_NX)
		valid = false
	} else if query.QType != nsT_A {
		valid = false
	}

	if valid {
		var label []byte
		if (query.ID & 1) != 0 {
			label = query.Labels.Primary.Label[:]
		} else {
			label = query.Labels.Secondary.Label[:]
		}
		ip4, ok := parseIP4Label(label)
		if !ok {
			reply.setRCode(nsR_NX)
			valid = false
		} else {
			copy(reply.RData[:], ip4)
		}
	}

	if !valid {
		reply.ANCount = 0
	}
	return reply.marshal(valid)
}

func (h *header) domainBytes() []byte {
	b := make([]byte, 0, 10)
	b = append(b, 5)
	b = append(b, h.Labels.Domain.Domain.Data[:]...)
	b = append(b, 2)
	b = append(b, h.Labels.Domain.TLD.Data[:]...)
	b = append(b, h.Labels.Domain.Root)
	return b
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func (h *header) unmarshal(b []byte) error {
	if len(b) < 44 {
		return fmt.Errorf("packet too short")
	}
	h.ID = binary.BigEndian.Uint16(b[0:2])
	h.Flags = binary.BigEndian.Uint16(b[2:4])
	h.QDCount = binary.BigEndian.Uint16(b[4:6])
	h.ANCount = binary.BigEndian.Uint16(b[6:8])
	h.NSCount = binary.BigEndian.Uint16(b[8:10])
	h.ARCount = binary.BigEndian.Uint16(b[10:12])
	h.Labels.Primary.Len = b[12]
	copy(h.Labels.Primary.Label[:], b[13:21])
	h.Labels.Secondary.Len = b[21]
	copy(h.Labels.Secondary.Label[:], b[22:30])
	// domain: 1+5, tld: 1+2, root: 1
	h.Labels.Domain.Domain.Len = b[30]
	copy(h.Labels.Domain.Domain.Data[:], b[31:36])
	h.Labels.Domain.TLD.Len = b[36]
	copy(h.Labels.Domain.TLD.Data[:], b[37:39])
	h.Labels.Domain.Root = b[39]
	h.QType = binary.BigEndian.Uint16(b[40:42])
	h.QClass = binary.BigEndian.Uint16(b[42:44])
	if len(b) >= 60 {
		h.PtrFlag = b[44]
		h.PtrOff = b[45]
		h.Type = binary.BigEndian.Uint16(b[46:48])
		h.Class = binary.BigEndian.Uint16(b[48:50])
		h.TTL = binary.BigEndian.Uint32(b[50:54])
		h.RDLength = binary.BigEndian.Uint16(b[54:56])
		copy(h.RData[:], b[56:60])
	}
	return nil
}

// marshal serializes the header. If full is false, only the first 44 bytes (through QClass) are returned (error response).
func (h *header) marshal(full bool) []byte {
	const headerLen = 60
	const errorLen = 44 // up to and including QClass
	size := errorLen
	if full {
		size = headerLen
	}
	b := make([]byte, size)
	binary.BigEndian.PutUint16(b[0:2], h.ID)
	binary.BigEndian.PutUint16(b[2:4], h.Flags)
	binary.BigEndian.PutUint16(b[4:6], h.QDCount)
	binary.BigEndian.PutUint16(b[6:8], h.ANCount)
	binary.BigEndian.PutUint16(b[8:10], h.NSCount)
	binary.BigEndian.PutUint16(b[10:12], h.ARCount)
	b[12] = h.Labels.Primary.Len
	copy(b[13:21], h.Labels.Primary.Label[:])
	b[21] = h.Labels.Secondary.Len
	copy(b[22:30], h.Labels.Secondary.Label[:])
	b[30] = h.Labels.Domain.Domain.Len
	copy(b[31:36], h.Labels.Domain.Domain.Data[:])
	b[36] = h.Labels.Domain.TLD.Len
	copy(b[37:39], h.Labels.Domain.TLD.Data[:])
	b[39] = h.Labels.Domain.Root
	binary.BigEndian.PutUint16(b[40:42], h.QType)
	binary.BigEndian.PutUint16(b[42:44], h.QClass)
	if full {
		b[44] = h.PtrFlag
		b[45] = h.PtrOff
		binary.BigEndian.PutUint16(b[46:48], h.Type)
		binary.BigEndian.PutUint16(b[48:50], h.Class)
		binary.BigEndian.PutUint32(b[50:54], h.TTL)
		binary.BigEndian.PutUint16(b[54:56], h.RDLength)
		copy(b[56:60], h.RData[:])
	}
	return b
}

func main() {
	port := flag.Int("port", 53, "UDP port to listen on (53 requires root)")
	domain := flag.String("domain", defaultDomain, "Domain suffix for rebinding (empty = use default rbndr.us)")
	flag.Parse()
	if strings.TrimSpace(*domain) == "" {
		*domain = defaultDomain
	}
	scanner := bufio.NewScanner(os.Stdin)
	fmt.Print("Rebinding IP: ")
	if !scanner.Scan() {
		log.Fatalf("read input: %v", scanner.Err())
	}
	rebindingIP := strings.TrimSpace(scanner.Text())
	fmt.Print("Access IP: ")
	if !scanner.Scan() {
		log.Fatalf("read input: %v", scanner.Err())
	}
	accessIP := strings.TrimSpace(scanner.Text())
	hostname, err := rebindHostname(rebindingIP, accessIP, *domain)
	if err != nil {
		log.Fatalf("invalid IP: %v", err)
	}
	fmt.Println("Generated hostname: ", hostname)
	fmt.Println("--------------------------------")
	log.Println("Starting DNS server...")
	log.Printf("hostname: %s", hostname)
	domainLabels := domainToLabels(*domain)
	if len(domainLabels) == 0 {
		log.Fatalf("invalid -domain %q", *domain)
	}
	addr := &net.UDPAddr{IP: net.IPv4(0, 0, 0, 0), Port: *port}
	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	defer conn.Close()
	log.Printf("rbndr DNS server listening on %s (domain suffix: %s)", conn.LocalAddr(), *domain)
	if err := runServer(conn, domainLabels); err != nil {
		log.Fatalf("server error: %v", err)
	}
	os.Exit(0)
}
