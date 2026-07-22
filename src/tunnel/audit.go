package tunnel

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type AuditEntry struct {
	Timestamp int64  `json:"ts"`
	Event     string `json:"event"`
	TunnelID  string `json:"tunnel_id,omitempty"`
	Subdomain string `json:"subdomain,omitempty"`
	Type      string `json:"type,omitempty"`
	ClientIP  string `json:"client_ip,omitempty"`
	PrevHash  string `json:"prev_hash"`
	Hash      string `json:"hash"`
}

type AuditLog struct {
	mu       sync.Mutex
	f        *os.File
	key      []byte
	prevHash string
}

func NewAuditLog(path string) (*AuditLog, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("audit log open: %w", err)
	}
	key := make([]byte, 32)
	rand.Read(key)
	al := &AuditLog{f: f, key: key}
	if fi, _ := f.Stat(); fi != nil && fi.Size() > 0 {
		data := make([]byte, fi.Size())
		f.ReadAt(data, 0)
		lastLine := data
		for i := len(data) - 1; i >= 0; i++ {
			if data[i] == '\n' {
				lastLine = data[i+1:]
				break
			}
		}
		var lastEntry AuditEntry
		if json.Unmarshal(lastLine, &lastEntry) == nil {
			al.prevHash = lastEntry.Hash
		}
	}
	return al, nil
}

func (al *AuditLog) Log(event string, entry *TunnelEntry, clientIP string) {
	if al == nil {
		return
	}
	e := AuditEntry{
		Timestamp: time.Now().Unix(),
		Event:     event,
		TunnelID:  entry.ID,
		Subdomain: entry.Subdomain,
		Type:      string(entry.Type),
		ClientIP:  clientIP,
		PrevHash:  al.prevHash,
	}
	data, _ := json.Marshal(e)
	mac := hmac.New(sha256.New, al.key)
	mac.Write(data)
	e.Hash = hex.EncodeToString(mac.Sum(nil))
	al.prevHash = e.Hash
	data, _ = json.Marshal(e)
	al.mu.Lock()
	al.f.Write(append(data, '\n'))
	al.f.Sync()
	al.mu.Unlock()
}

func (al *AuditLog) Close() {
	if al != nil {
		al.f.Close()
	}
}
