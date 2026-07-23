package tunnel

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/flynn/noise"
)

// GenerateNoiseKeypair generates a Curve25519 keypair for the Noise Protocol NK
// pattern, returned hex-encoded. Backs the `skink noise-keygen` command.
func GenerateNoiseKeypair() (string, string, error) {
	kp, err := noise.DH25519.GenerateKeypair(rand.Reader)
	if err != nil {
		return "", "", fmt.Errorf("generate keypair: %w", err)
	}
	return hex.EncodeToString(kp.Private), hex.EncodeToString(kp.Public), nil
}
