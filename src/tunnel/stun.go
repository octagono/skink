package tunnel

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

type stunHeader struct {
	Type   uint16
	Length uint16
	Magic  uint32
	TxID   [12]byte
}

func stunBindingRequest() []byte {
	hdr := stunHeader{Type: 0x0001, Magic: 0x2112A442}
	rand.Read(hdr.TxID[:])
	b := make([]byte, 20)
	binary.BigEndian.PutUint16(b[0:2], hdr.Type)
	binary.BigEndian.PutUint16(b[2:4], 0)
	binary.BigEndian.PutUint32(b[4:8], hdr.Magic)
	copy(b[8:20], hdr.TxID[:])
	return b
}

func stunParseMappedAddr(data []byte) (string, error) {
	if len(data) < 20 {
		return "", fmt.Errorf("stun response too short")
	}
	magic := binary.BigEndian.Uint32(data[4:8])
	if magic != 0x2112A442 {
		return "", fmt.Errorf("bad stun magic")
	}
	length := int(binary.BigEndian.Uint16(data[2:4]))
	pos := 20
	for pos+4 < 20+length {
		attrType := binary.BigEndian.Uint16(data[pos : pos+2])
		attrLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4
		if pos+attrLen > len(data) {
			break
		}
		if attrType == 0x0020 || attrType == 0x0001 {
			addr := net.IP(data[pos+4 : pos+8])
			port := binary.BigEndian.Uint16(data[pos+2 : pos+4])
			return fmt.Sprintf("%s:%d", addr, port), nil
		}
		pos += attrLen
		if pos%4 != 0 {
			pos += 4 - pos%4
		}
	}
	return "", fmt.Errorf("no mapped address")
}

func StunQuery(server string, timeout time.Duration) (string, error) {
	conn, err := net.DialTimeout("udp", server, timeout)
	if err != nil {
		return "", fmt.Errorf("stun dial: %w", err)
	}
	defer conn.Close()
	req := stunBindingRequest()
	if _, err := conn.Write(req); err != nil {
		return "", fmt.Errorf("stun write: %w", err)
	}
	resp := make([]byte, 1500)
	conn.SetReadDeadline(time.Now().Add(timeout))
	n, err := conn.Read(resp)
	if err != nil {
		return "", fmt.Errorf("stun read: %w", err)
	}
	return stunParseMappedAddr(resp[:n])
}
