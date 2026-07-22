package tunnel

import (
	"crypto/sha256"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/octagono/skink/src/comm"
	"github.com/octagono/skink/src/crypt"
	"github.com/octagono/skink/src/message"
	log "github.com/schollz/logger"
	"github.com/schollz/pake/v3"
)

type EmbeddedRelay struct {
	port     int
	password string
	listener net.Listener
	quit     chan struct{}
	wg       sync.WaitGroup
}

func NewEmbeddedRelay(port int, password string) *EmbeddedRelay {
	return &EmbeddedRelay{
		port:     port,
		password: password,
		quit:     make(chan struct{}),
	}
}

func (e *EmbeddedRelay) Start() error {
	addr := fmt.Sprintf(":%d", e.port)
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("embed relay listen: %w", err)
	}
	e.listener = ln
	e.wg.Add(1)
	go e.acceptLoop()
	log.Infof("embedded relay on %s (P2P fallback)", addr)
	return nil
}

func (e *EmbeddedRelay) Stop() {
	close(e.quit)
	if e.listener != nil {
		e.listener.Close()
	}
	e.wg.Wait()
}

func (e *EmbeddedRelay) Addr() string {
	if e.listener != nil {
		return e.listener.Addr().String()
	}
	return ""
}

func (e *EmbeddedRelay) acceptLoop() {
	defer e.wg.Done()
	for {
		conn, err := e.listener.Accept()
		if err != nil {
			select {
			case <-e.quit:
				return
			default:
				continue
			}
		}
		go e.handle(conn)
	}
}

func (e *EmbeddedRelay) handle(conn net.Conn) {
	defer conn.Close()
	c := comm.New(conn)
	key, err := e.pakeHandshake(c)
	if err != nil {
		log.Debugf("embed relay PAKE: %v", err)
		return
	}
	msgType, payload, err := ReceiveTunnelMessage(c, key)
	if err != nil {
		log.Debugf("embed relay receive: %v", err)
		return
	}
	switch msgType {
	case message.TypeTunnelRegister:
		var reg TunnelRegistration
		if err := DecodePayload(payload, &reg); err != nil {
			return
		}
		info := TunnelInfo{
			TunnelID:   generateTunnelID(),
			PublicURL:  fmt.Sprintf("direct://%s:%d", reg.LocalAddr, e.port),
			Subdomain:  reg.Subdomain,
			AssignedAt: time.Now().Format(time.RFC3339),
		}
		if err := SendTunnelMessage(c, key, message.TypeTunnelRegistered, info); err != nil {
			return
		}
		log.Infof("embed relay: tunnel %s → %s", info.Subdomain, reg.LocalAddr)
		go e.controlLoop(c, key)
	}
}

func (e *EmbeddedRelay) controlLoop(c *comm.Comm, key []byte) {
	ticker := time.NewTicker(15 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-e.quit:
			return
		case <-ticker.C:
			if err := SendTunnelMessage(c, key, message.TypeHeartbeat, HeartbeatMessage{}); err != nil {
				return
			}
		default:
			_, _, err := ReceiveTunnelMessage(c, key)
			if err != nil {
				return
			}
		}
	}
}

func (e *EmbeddedRelay) pakeHandshake(c *comm.Comm) ([]byte, error) {
	weakKey := sha256Hash(e.password)
	p, err := pake.InitCurve(weakKey, 1, "siec")
	if err != nil {
		return nil, fmt.Errorf("pake init: %w", err)
	}
	data, err := c.Receive()
	if err != nil {
		return nil, fmt.Errorf("pake receive: %w", err)
	}
	if err := p.Update(data); err != nil {
		return nil, fmt.Errorf("pake update: %w", err)
	}
	sessionKey, err := p.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("session key: %w", err)
	}
	if err := c.Send(p.Bytes()); err != nil {
		return nil, fmt.Errorf("pake send: %w", err)
	}
	strongKey := sha256Sum(sessionKey)
	encKey, salt, err := crypt.New(strongKey, nil)
	if err != nil {
		return nil, fmt.Errorf("crypt new: %w", err)
	}
	if err := c.Send(salt); err != nil {
		return nil, fmt.Errorf("salt send: %w", err)
	}
	if _, err := c.Receive(); err != nil {
		return nil, fmt.Errorf("ok receive: %w", err)
	}
	if err := c.Send(encKey); err != nil {
		return nil, fmt.Errorf("ok send: %w", err)
	}
	return encKey, nil
}

func sha256Hash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func sha256Sum(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
