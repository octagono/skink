package tunnel

import (
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
)

func generateECDHKey() (*ecdh.PrivateKey, error) {
	return ecdh.P256().GenerateKey(rand.Reader)
}

func deriveRekeyKey(priv *ecdh.PrivateKey, oldKey, peerPublic []byte) ([]byte, error) {
	pub, err := ecdh.P256().NewPublicKey(peerPublic)
	if err != nil {
		return nil, fmt.Errorf("parse peer public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh: %w", err)
	}
	h := sha256.Sum256(append(oldKey, shared...))
	return h[:], nil
}

func doRekeyServerSide(oldKey, clientPublic []byte) ([]byte, []byte, error) {
	priv, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("generate ecdh key: %w", err)
	}
	serverPublic := priv.PublicKey().Bytes()
	pub, err := ecdh.P256().NewPublicKey(clientPublic)
	if err != nil {
		return nil, nil, fmt.Errorf("parse client public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh: %w", err)
	}
	newKey := sha256.Sum256(append(oldKey, shared...))
	return newKey[:], serverPublic, nil
}
