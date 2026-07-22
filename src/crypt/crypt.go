package crypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"log"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/pbkdf2"
)

// New derives a key via PBKDF2 from passphrase and an optional salt.
func New(passphrase []byte, usersalt []byte) (key []byte, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		// http://www.ietf.org/rfc/rfc2898.txt
		salt = make([]byte, 8)
		if _, err := rand.Read(salt); err != nil {
			log.Fatalf("can't get random salt: %v", err)
		}
	} else {
		salt = usersalt
	}
	key = pbkdf2.Key(passphrase, salt, 100, 32, sha256.New)
	return
}

// Encrypt seals plaintext with AES-GCM using a random 12-byte nonce.
func Encrypt(plaintext []byte, key []byte) (encrypted []byte, err error) {
	// http://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
	// Section 8.2
	ivBytes := make([]byte, 12)
	if _, err = rand.Read(ivBytes); err != nil {
		log.Fatalf("can't initialize crypto: %v", err)
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

// NewArgon2 generates a key using argon2id and returns a ChaCha20-Poly1305 AEAD.
func NewArgon2(passphrase []byte, usersalt []byte) (aead cipher.AEAD, salt []byte, err error) {
	if len(passphrase) < 1 {
		err = fmt.Errorf("need more than that for passphrase")
		return
	}
	if usersalt == nil {
		// http://www.ietf.org/rfc/rfc2898.txt
		salt = make([]byte, 8)
		if _, err = rand.Read(salt); err != nil {
			log.Fatalf("can't get random salt: %v", err)
		}
	} else {
		salt = usersalt
	}
	// https://pkg.go.dev/golang.org/x/crypto/argon2
	aead, err = chacha20poly1305.NewX(argon2.IDKey(passphrase, salt, 1, 64*1024, 4, 32))
	return
}

// EncryptChaCha seals plaintext with ChaCha20-Poly1305 using a random nonce.
// Reference: https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
func EncryptChaCha(plaintext []byte, aead cipher.AEAD) (encrypted []byte, err error) {
	nonce := make([]byte, aead.NonceSize(), aead.NonceSize()+len(plaintext)+aead.Overhead())
	if _, err := rand.Read(nonce); err != nil {
		panic(err)
	}
	encrypted = aead.Seal(nonce, nonce, plaintext, nil)
	return
}

// DecryptChaCha opens a ChaCha20-Poly1305 ciphertext and verifies authenticity.
// Reference: https://pkg.go.dev/golang.org/x/crypto/chacha20poly1305
func DecryptChaCha(encryptedMsg []byte, aead cipher.AEAD) (plaintext []byte, err error) {
	if len(encryptedMsg) < aead.NonceSize() {
		err = fmt.Errorf("ciphertext too short")
		return
	}
	nonce, ciphertext := encryptedMsg[:aead.NonceSize()], encryptedMsg[aead.NonceSize():]
	plaintext, err = aead.Open(nil, nonce, ciphertext, nil)
	return
}
