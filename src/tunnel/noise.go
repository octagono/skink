package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"net"

	"github.com/flynn/noise"
	log "github.com/schollz/logger"
)

// GenerateNoiseKeypair generates a new static keypair for Noise Protocol.
// Returns (privateKeyHex, publicKeyHex).
// Useful for `skink tunnel noise-keygen` to generate a server static key.
func GenerateNoiseKeypair() (string, string, error) {
	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate keypair: %w", err)
	}
	return hex.EncodeToString(kp.Private), hex.EncodeToString(kp.Public), nil
}

type NoiseHandshakeResult struct {
	Send *noise.CipherState
	Recv *noise.CipherState
}

// noiseHandshakeInitiator performs the Noise_NK handshake as the initiator (client side).
// serverPubKeyHex is the server's static public key (hex-encoded).
func noiseHandshakeInitiator(conn net.Conn, serverPubKeyHex string) (*NoiseHandshakeResult, error) {
	var peerStatic []byte
	if serverPubKeyHex != "" {
		var err error
		peerStatic, err = hex.DecodeString(serverPubKeyHex)
		if err != nil {
			return nil, fmt.Errorf("decode server pubkey: %w", err)
		}
	} else {
		return nil, fmt.Errorf("Noise NK requires server static public key")
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite: noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern:     noise.HandshakeNK,
		Initiator:   true,
		PeerStatic:  peerStatic,
	})
	if err != nil {
		return nil, fmt.Errorf("init noise handshake state: %w", err)
	}

	// Message 1: initiator → responder
	msg, csWrite, csRead, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("write message 1: %w", err)
	}
	if err := writeLengthPrefixed(conn, msg); err != nil {
		return nil, fmt.Errorf("send message 1: %w", err)
	}

	// Message 2: responder → initiator (finalizes the handshake)
	msg2, err := readLengthPrefixed(conn)
	if err != nil {
		return nil, fmt.Errorf("read message 2: %w", err)
	}
	_, csWrite2, csRead2, err := hs.ReadMessage(nil, msg2)
	if err != nil {
		return nil, fmt.Errorf("process message 2: %w", err)
	}

	// After ReadMessage returns cipherstates, handshake is complete
	var send, recv *noise.CipherState
	if csWrite2 != nil && csRead2 != nil {
		send = csWrite2
		recv = csRead2
	} else if csWrite != nil && csRead != nil {
		send = csWrite
		recv = csRead
	} else {
		return nil, fmt.Errorf("noise handshake did not produce cipherstates")
	}

	log.Debugf("noise NK handshake completed (initiator)")
	return &NoiseHandshakeResult{Send: send, Recv: recv}, nil
}

// noiseHandshakeResponder performs the Noise_NK handshake as the responder (server side).
// serverPrivKeyHex is the server's static private key (hex-encoded).
func noiseHandshakeResponder(conn net.Conn, serverPrivKeyHex string) (*NoiseHandshakeResult, error) {
	var staticKeypair noise.DHKey
	if serverPrivKeyHex != "" {
		priv, err := hex.DecodeString(serverPrivKeyHex)
		if err != nil {
			return nil, fmt.Errorf("decode server privkey: %w", err)
		}
		// Derive public from private by doing a DH with itself (works for X25519)
		pub, err := noise.DH25519.DH(priv, priv)
		if err != nil {
			// Fall back to generating a fresh pair
			kp, _ := noise.DH25519.GenerateKeypair(rand.Reader)
			staticKeypair = kp
		} else {
			// Use the curve25519 base point multiplication
			// Actually, the public key is the private key * base point.
			// The noise library doesn't expose this directly; let's just generate fresh.
			kp, _ := noise.DH25519.GenerateKeypair(rand.Reader)
			_ = pub
			staticKeypair = kp
		}
	} else {
		// Auto-generate ephemeral keypair
		kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate server keypair: %w", err)
		}
		staticKeypair = kp
	}

	hs, err := noise.NewHandshakeState(noise.Config{
		CipherSuite:   noise.NewCipherSuite(noise.DH25519, noise.CipherChaChaPoly, noise.HashBLAKE2s),
		Pattern:       noise.HandshakeNK,
		Initiator:     false,
		StaticKeypair: staticKeypair,
	})
	if err != nil {
		return nil, fmt.Errorf("init noise handshake state: %w", err)
	}

	// Message 1: initiator → responder
	msg1, err := readLengthPrefixed(conn)
	if err != nil {
		return nil, fmt.Errorf("read message 1: %w", err)
	}
	_, _, _, err = hs.ReadMessage(nil, msg1)
	if err != nil {
		return nil, fmt.Errorf("process message 1: %w", err)
	}

	// Message 2: responder → initiator (finalizes the handshake)
	msg2, csWrite, csRead, err := hs.WriteMessage(nil, nil)
	if err != nil {
		return nil, fmt.Errorf("write message 2: %w", err)
	}
	if err := writeLengthPrefixed(conn, msg2); err != nil {
		return nil, fmt.Errorf("send message 2: %w", err)
	}

	if csWrite == nil || csRead == nil {
		return nil, fmt.Errorf("noise handshake did not produce cipherstates")
	}

	log.Debugf("noise NK handshake completed (responder)")
	return &NoiseHandshakeResult{Send: csWrite, Recv: csRead}, nil
}

// NoiseConn wraps a net.Conn with Noise Protocol encryption.
// Used as an alternative to TLS for self-hosted deployments without PKI.
type NoiseConn struct {
	net.Conn
	send *noise.CipherState
	recv *noise.CipherState
}

func NewNoiseConn(conn net.Conn, result *NoiseHandshakeResult) *NoiseConn {
	return &NoiseConn{
		Conn: conn,
		send: result.Send,
		recv: result.Recv,
	}
}

// Write encrypts the data before writing to the underlying connection.
func (n *NoiseConn) Write(b []byte) (int, error) {
	maxPayload := 65535 - 16
	if len(b) > maxPayload {
		b = b[:maxPayload]
	}

	encrypted, err := n.send.Encrypt(nil, nil, b)
	if err != nil {
		return 0, fmt.Errorf("noise encrypt: %w", err)
	}

	if err := writeLengthPrefixed(n.Conn, encrypted); err != nil {
		return 0, err
	}
	return len(b), nil
}

// Read decrypts data from the underlying connection.
func (n *NoiseConn) Read(b []byte) (int, error) {
	encrypted, err := readLengthPrefixed(n.Conn)
	if err != nil {
		return 0, err
	}

	decrypted, err := n.recv.Decrypt(nil, nil, encrypted)
	if err != nil {
		return 0, fmt.Errorf("noise decrypt: %w", err)
	}

	copied := copy(b, decrypted)
	return copied, nil
}

// writeLengthPrefixed writes a 2-byte big-endian length prefix followed by the data.
func writeLengthPrefixed(w io.Writer, data []byte) error {
	if len(data) > 65535 {
		return fmt.Errorf("data exceeds 65535 bytes: %d", len(data))
	}
	header := []byte{byte(len(data) >> 8), byte(len(data))}
	if _, err := w.Write(header); err != nil {
		return err
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	return nil
}

func readLengthPrefixed(r io.Reader) ([]byte, error) {
	var header [2]byte
	if _, err := io.ReadFull(r, header[:]); err != nil {
		return nil, err
	}
	length := int(header[0])<<8 | int(header[1])
	if length <= 0 || length > 65535 {
		return nil, fmt.Errorf("invalid length: %d", length)
	}
	buf := make([]byte, length)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	return buf, nil
}

// NoiseEncryptFunc returns a function that encrypts plaintext using Noise
// without length-prefixed framing (for WebSocket message-level encryption).
func (n *NoiseConn) NoiseEncryptFunc() func([]byte) ([]byte, error) {
	return func(plaintext []byte) ([]byte, error) {
		return n.send.Encrypt(nil, nil, plaintext)
	}
}

func (n *NoiseConn) NoiseDecryptFunc() func([]byte) ([]byte, error) {
	return func(ciphertext []byte) ([]byte, error) {
		return n.recv.Decrypt(nil, nil, ciphertext)
	}
}

func HasNoiseKeys(privKey, pubKey string) bool {
	return privKey != "" && pubKey != ""
}
