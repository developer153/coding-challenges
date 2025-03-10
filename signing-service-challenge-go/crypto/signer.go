package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"errors"
)

var ErrDecode = errors.New("decoding private key failed")

// Signer defines a contract for different types of signing implementations.
type Signer interface {
	Sign(dataToBeSigned []byte) ([]byte, error)
}

// TODO: implement RSA and ECDSA signing ...

var ErrInvalidAlgorithm = errors.New("invalid algorithm")

func NewSigner(algorithm string, privateKey []byte) (Signer, error) {
	switch algorithm {
	case "ECC":
		marshaller := NewECCMarshaler()
		keyPair, err := marshaller.Decode(privateKey)
		if err != nil {
			return nil, ErrDecode
		}
		return &ECCSigner{
			privateKey: keyPair.Private,
		}, nil
	case "RSA":
		marshaller := NewRSAMarshaler()
		keyPair, err := marshaller.Unmarshal(privateKey)
		if err != nil {
			return nil, ErrDecode
		}
		return &RSASigner{
			privateKey: keyPair.Private,
		}, nil
	default:
		return nil, ErrInvalidAlgorithm
	}
}

type RSASigner struct {
	privateKey *rsa.PrivateKey
}

type ECCSigner struct {
	privateKey *ecdsa.PrivateKey
}

func (s *RSASigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	bytes := sha256.Sum256(dataToBeSigned)
	return rsa.SignPKCS1v15(nil, s.privateKey, crypto.SHA256, bytes[:])
}

func (s *ECCSigner) Sign(dataToBeSigned []byte) ([]byte, error) {
	bytes := sha256.Sum256(dataToBeSigned)
	return ecdsa.SignASN1(rand.Reader, s.privateKey, bytes[:])
}
