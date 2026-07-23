package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"

	"golang.org/x/crypto/pbkdf2"
)

// New derives a key via PBKDF2 from passphrase and an optional salt.
func New(passphrase []byte, usersalt []byte) (key []byte, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		salt = make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, nil, fmt.Errorf("can't get random salt: %w", err)
		}
	} else {
		salt = usersalt
	}
	// 600,000 iterations per NIST SP 800-132 recommendation for PBKDF2-HMAC-SHA256.
	// NOTE: Changing this value is a protocol-breaking change — both sender and
	// receiver must use the same iteration count. Both sides run the same binary
	// version, so this is safe for ad-hoc transfers.
	key = pbkdf2.Key(passphrase, salt, 600000, 32, sha256.New)
	return
}

// Encrypt seals plaintext with AES-GCM using a random 12-byte nonce.
func Encrypt(plaintext []byte, key []byte) (encrypted []byte, err error) {
	ivBytes := make([]byte, 12)
	if _, err = rand.Read(ivBytes); err != nil {
		return nil, fmt.Errorf("can't initialize crypto: %w", err)
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	encrypted = aesgcm.Seal(nil, ivBytes, plaintext, nil)
	encrypted = append(ivBytes, encrypted...)
	return
}

func Decrypt(encrypted []byte, key []byte) (plaintext []byte, err error) {
	if len(encrypted) < 13 {
		err = fmt.Errorf("incorrect passphrase")
		return
	}
	b, err := aes.NewCipher(key)
	if err != nil {
		return
	}
	aesgcm, err := cipher.NewGCM(b)
	if err != nil {
		return
	}
	plaintext, err = aesgcm.Open(nil, encrypted[:12], encrypted[12:], nil)
	return
}
