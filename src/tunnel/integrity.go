package tunnel

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"hash"
	"io"
	"net"
	"time"
)

type integrityConn struct {
	conn net.Conn
	mac  hash.Hash
}

func newIntegrityConn(conn net.Conn, key []byte) *integrityConn {
	return &integrityConn{
		conn: conn,
		mac:  hmac.New(sha256.New, key),
	}
}

func (c *integrityConn) Read(b []byte) (int, error) {
	var tagLen [2]byte
	if _, err := io.ReadFull(c.conn, tagLen[:]); err != nil {
		return 0, err
	}
	tagSize := int(binary.BigEndian.Uint16(tagLen[:]))
	if tagSize > 64 {
		return 0, fmt.Errorf("integrity tag too large: %d", tagSize)
	}
	tag := make([]byte, tagSize)
	if _, err := io.ReadFull(c.conn, tag); err != nil {
		return 0, err
	}
	var dataLen [4]byte
	if _, err := io.ReadFull(c.conn, dataLen[:]); err != nil {
		return 0, err
	}
	dataSize := int(binary.BigEndian.Uint32(dataLen[:]))
	if dataSize > len(b) {
		return 0, fmt.Errorf("buffer too small: %d < %d", len(b), dataSize)
	}
	n, err := io.ReadFull(c.conn, b[:dataSize])
	if err != nil {
		return n, err
	}
	c.mac.Reset()
	c.mac.Write(b[:dataSize])
	expected := c.mac.Sum(nil)
	if !hmac.Equal(tag, expected) {
		return n, fmt.Errorf("integrity check failed")
	}
	return n, nil
}

func (c *integrityConn) Write(b []byte) (int, error) {
	c.mac.Reset()
	c.mac.Write(b)
	tag := c.mac.Sum(nil)
	tagLen := make([]byte, 2)
	binary.BigEndian.PutUint16(tagLen, uint16(len(tag)))
	dataLen := make([]byte, 4)
	binary.BigEndian.PutUint32(dataLen, uint32(len(b)))
	header := append(tagLen, tag...)
	header = append(header, dataLen...)
	if _, err := c.conn.Write(header); err != nil {
		return 0, err
	}
	return c.conn.Write(b)
}

func (c *integrityConn) Close() error                       { return c.conn.Close() }
func (c *integrityConn) LocalAddr() net.Addr                { return c.conn.LocalAddr() }
func (c *integrityConn) RemoteAddr() net.Addr               { return c.conn.RemoteAddr() }
func (c *integrityConn) SetDeadline(t time.Time) error      { return c.conn.SetDeadline(t) }
func (c *integrityConn) SetReadDeadline(t time.Time) error  { return c.conn.SetReadDeadline(t) }
func (c *integrityConn) SetWriteDeadline(t time.Time) error { return c.conn.SetWriteDeadline(t) }
