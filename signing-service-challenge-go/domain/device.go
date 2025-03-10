package domain

import (
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/crypto"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"github.com/google/uuid"
)

var (
	ErrExists           = errors.New("already exists")
	ErrNotFound         = errors.New("not found")
	ErrModified         = errors.New("concurrent modifications")
	ErrInvalidUUID      = errors.New("invalid uuid")
	ErrInvalidAlgorithm = errors.New("invalid algorithm")
)

type ISignatureDeviceDomain interface {
	CreateSignatureDevice(id string, algorithm string, label string) (SignatureDevice, error)
	ReadSignatureDevice(id string) (SignatureDevice, error)
	SignTransaction(id, data string) (Signature, error)
	ReadSignatureDevices() []SignatureDevice
}

type SignatureDeviceDomain struct {
	db persistence.ISignatureDeviceDb
}

func NewSignatureDeviceDomain(db persistence.ISignatureDeviceDb) ISignatureDeviceDomain {
	return &SignatureDeviceDomain{
		db: db,
	}
}

type SignatureDevice struct {
	Id               string
	Algorithm        string
	Label            string
	SignatureCounter int
	LastSignature    string
}

type Signature struct {
	Signature  string
	SignedData string
}

func (d *SignatureDeviceDomain) CreateSignatureDevice(id, algorithm, label string) (SignatureDevice, error) {
	err := uuid.Validate(id)
	if err != nil {
		return SignatureDevice{}, ErrInvalidUUID
	}

	publicKey, privateKey, err := crypto.NewKeyPair(algorithm)
	if err != nil {
		if errors.Is(err, crypto.ErrInvalidAlgorithm) {
			return SignatureDevice{}, ErrInvalidAlgorithm
		}
		return SignatureDevice{}, err
	}

	device := persistence.SignatureDevice{
		Id:            persistence.Id(id),
		Algorithm:     algorithm,
		Label:         label,
		PublicKey:     publicKey,
		PrivateKey:    privateKey,
		LastSignature: base64.StdEncoding.EncodeToString([]byte(id)),
	}

	err = d.db.Store(device)
	if err != nil {
		if errors.Is(err, persistence.ErrExists) {
			return SignatureDevice{}, ErrExists
		}
		return SignatureDevice{}, err
	}
	return d.ReadSignatureDevice(id)
}

func (d *SignatureDeviceDomain) ReadSignatureDevice(id string) (SignatureDevice, error) {
	device, err := d.db.FindById(persistence.Id(id))
	if err != nil {
		if errors.Is(err, persistence.ErrNotFound) {
			return SignatureDevice{}, ErrNotFound
		}
		return SignatureDevice{}, err
	}
	return SignatureDevice{
		Id:               string(device.Id),
		Algorithm:        device.Algorithm,
		Label:            device.Label,
		SignatureCounter: device.SignatureCounter,
		LastSignature:    device.LastSignature,
	}, nil
}

func (d *SignatureDeviceDomain) SignTransaction(id, data string) (Signature, error) {
	device, err := d.db.FindById(persistence.Id(id))
	if err != nil {
		if errors.Is(err, persistence.ErrNotFound) {
			return Signature{}, ErrNotFound
		}
		return Signature{}, err
	}

	signedData := fmt.Sprintf("%d_%s_%s", device.SignatureCounter, data, device.LastSignature)
	signer, err := crypto.NewSigner(device.Algorithm, device.PrivateKey)
	if err != nil {
		return Signature{}, err
	}
	signature, err := signer.Sign([]byte(signedData))
	if err != nil {
		return Signature{}, err
	}
	base64Signature := base64.StdEncoding.EncodeToString(signature)

	newDevice := persistence.SignatureDevice{
		Id:               persistence.Id(id),
		Algorithm:        device.Algorithm,
		Label:            device.Label,
		PublicKey:        device.PublicKey,
		PrivateKey:       device.PrivateKey,
		SignatureCounter: device.SignatureCounter + 1,
		LastSignature:    base64Signature,
	}

	err = d.db.CompareAndSwap(device, newDevice)
	if err != nil {
		if errors.Is(err, persistence.ErrModified) {
			return Signature{}, ErrModified
		}
		return Signature{}, err
	}
	return Signature{
		Signature:  base64Signature,
		SignedData: signedData,
	}, nil
}

func (d *SignatureDeviceDomain) ReadSignatureDevices() []SignatureDevice {
	devices := d.db.FindAll()
	result := make([]SignatureDevice, 0)
	for _, device := range devices {
		result = append(result, SignatureDevice{
			Id:               string(device.Id),
			Algorithm:        device.Algorithm,
			Label:            device.Label,
			SignatureCounter: device.SignatureCounter,
			LastSignature:    device.LastSignature,
		})
	}
	return result
}
