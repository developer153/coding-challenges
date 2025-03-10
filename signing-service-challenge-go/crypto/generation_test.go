package crypto

import (
	"testing"
)

func TestNewKeyPair_OkECC(t *testing.T) {
	_, _, err := NewKeyPair("ECC")

	assertEqual(t, nil, err)
}

func TestNewKeyPair_OkRSA(t *testing.T) {
	_, _, err := NewKeyPair("RSA")

	assertEqual(t, nil, err)
}

func TestNewKeyPair_ErrInvalidAlgorithm(t *testing.T) {
	_, _, err := NewKeyPair("ED25519")

	assertEqual(t, ErrInvalidAlgorithm, err)
}
