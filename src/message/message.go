package message

import (
	"encoding/json"

	"github.com/octagono/skink/src/comm"
	"github.com/octagono/skink/src/compress"
	"github.com/octagono/skink/src/crypt"
	log "github.com/schollz/logger"
)

type Type string

const (
	TypePAKE           Type = "pake"
	TypeExternalIP     Type = "externalip"
	TypeFinished       Type = "finished"
	TypeError          Type = "error"
	TypeCloseRecipient Type = "close-recipient"
	TypeCloseSender    Type = "close-sender"
	TypeRecipientReady Type = "recipientready"
	TypeFileInfo       Type = "fileinfo"

	// Tunnel protocol message types
	TypeTunnelRegister   Type = "tunnel-register"
	TypeTunnelRegistered Type = "tunnel-registered"
	TypeTunnelError      Type = "tunnel-error"
	TypeReqProxy         Type = "req-proxy"
	TypeProxyConnected   Type = "proxy-connected"
	TypeHeartbeat        Type = "heartbeat"
	TypeTunnelClose      Type = "tunnel-close"
	TypeExecRequest      Type = "exec-request"
	TypeExecResponse     Type = "exec-response"

	// Private sharing mode
	TypeAccessRequest Type = "access-request"
	TypeAccessGranted Type = "access-granted"
	TypeAccessDenied  Type = "access-denied"

	// Session resumption
	TypeTunnelResume Type = "tunnel-resume"

	// Forward secrecy rekeying
	TypeRekey    Type = "rekey"
	TypeRekeyAck Type = "rekey-ack"

	// Connection migration
	TypeTunnelMigrate Type = "tunnel-migrate"

	// Adaptive window probing
	TypeRTTProbe Type = "rtt-probe"

	// Relay HA sync
	TypeTunnelSync       Type = "tunnel-sync"
	TypeTunnelSyncRemove Type = "tunnel-sync-remove"

	// Multi-hop relay path healing
	TypeRelayAdvertise Type = "relay-advertise"
	TypeRelayWithdraw  Type = "relay-withdraw"
	TypePathProbe      Type = "path-probe"
	TypePathProbeReply Type = "path-probe-reply"
)

type Message struct {
	Type    Type   `json:"t,omitempty"`
	Message string `json:"m,omitempty"`
	Bytes   []byte `json:"b,omitempty"`
	Bytes2  []byte `json:"b2,omitempty"`
	Num     int    `json:"n,omitempty"`
}

func (m Message) String() string {
	b, _ := json.Marshal(m)
	return string(b)
}

func Send(c *comm.Comm, key []byte, m Message) (err error) {
	mSend, err := Encode(key, m)
	if err != nil {
		return
	}
	err = c.Send(mSend)
	return
}

func Encode(key []byte, m Message) (b []byte, err error) {
	b, _ = json.Marshal(m)
	b = compress.Compress(b)
	if key != nil {
		log.Debugf("writing %s message (encrypted)", m.Type)
		b, err = crypt.Encrypt(b, key)
	} else {
		log.Debugf("writing %s message (unencrypted)", m.Type)
	}
	return
}

func Decode(key []byte, b []byte) (m Message, err error) {
	if key != nil {
		b, err = crypt.Decrypt(b, key)
		if err != nil {
			return
		}
	}
	b = compress.Decompress(b)
	err = json.Unmarshal(b, &m)
	if err == nil {
		if key != nil {
			log.Debugf("read %s message (encrypted)", m.Type)
		} else {
			log.Debugf("read %s message (unencrypted)", m.Type)
		}
	}
	return
}
