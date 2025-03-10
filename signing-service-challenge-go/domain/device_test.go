package domain

import (
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, expected any, actual any) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected %v, actual %v", expected, actual)
	}
}

func assertNotEmpty(t *testing.T, actual []byte) {
	if len(actual) == 0 {
		t.Errorf("Expected not empty, actual %v", actual)
	}
}

type SignatureDeviceInMemoryDbStub struct {
	StoreFunc          func(device persistence.SignatureDevice) error
	FindByIdFunc       func(id persistence.Id) (persistence.SignatureDevice, error)
	CompareAndSwapFunc func(old, new persistence.SignatureDevice) error
	FindAllFunc        func() []persistence.SignatureDevice
}

func (s *SignatureDeviceInMemoryDbStub) Store(device persistence.SignatureDevice) error {
	return s.StoreFunc(device)
}

func (s *SignatureDeviceInMemoryDbStub) FindById(id persistence.Id) (persistence.SignatureDevice, error) {
	return s.FindByIdFunc(id)
}

func (s *SignatureDeviceInMemoryDbStub) CompareAndSwap(old, new persistence.SignatureDevice) error {
	return s.CompareAndSwapFunc(old, new)
}

func (s *SignatureDeviceInMemoryDbStub) FindAll() []persistence.SignatureDevice {
	return s.FindAllFunc()
}

var device1 = persistence.SignatureDevice{
	Id:        "550e8400-e29b-11d4-a716-446655440000",
	Algorithm: "ECC",
	Label:     "device1",
	PublicKey: []byte(`-----BEGIN PUBLIC_KEY-----
MHYwEAYHKoZIzj0CAQYFK4EEACIDYgAEqSgKeSCQnv/zGms6aPTQLwobQPZzdbRD
UlCUSZX/7szy2JJMo11Z2HLUILXqk6Tb7cJNXlDZROusqAuS3sT8ozyfMacUg/qb
vwso5rJ2csBlUuNqm9lKd5zHWL4CjIgQ
-----END PUBLIC_KEY-----`),
	PrivateKey: []byte(`-----BEGIN PRIVATE_KEY-----
MIGkAgEBBDA10Qv12By0KByh0aaUZCmcwCSdhkMecHgRoYY3U2iiTmR4QU2iQbD6
IoeIHX10dgWgBwYFK4EEACKhZANiAASpKAp5IJCe//Maazpo9NAvChtA9nN1tENS
UJRJlf/uzPLYkkyjXVnYctQgteqTpNvtwk1eUNlE66yoC5LexPyjPJ8xpxSD+pu/
CyjmsnZywGVS42qb2Up3nMdYvgKMiBA=
-----END PRIVATE_KEY-----`),
	SignatureCounter: 0,
	LastSignature:    "NTUwZTg0MDAtZTI5Yi0xMWQ0LWE3MTYtNDQ2NjU1NDQwMDAw",
}

func TestCreateSignatureDevice_Ok(t *testing.T) {
	var storeDevice persistence.SignatureDevice
	db := &SignatureDeviceInMemoryDbStub{
		FindByIdFunc: func(id persistence.Id) (persistence.SignatureDevice, error) {
			return storeDevice, nil
		},
		StoreFunc: func(device persistence.SignatureDevice) error {
			storeDevice = device
			return nil
		},
	}
	domain := NewSignatureDeviceDomain(db)

	device, err := domain.CreateSignatureDevice("550e8400-e29b-11d4-a716-446655440000", "ECC", "")

	assertEqual(t, nil, err)
	assertEqual(t, SignatureDevice{
		Id:               "550e8400-e29b-11d4-a716-446655440000",
		Algorithm:        "ECC",
		Label:            "",
		SignatureCounter: 0,
		LastSignature:    "NTUwZTg0MDAtZTI5Yi0xMWQ0LWE3MTYtNDQ2NjU1NDQwMDAw",
	}, device)
	assertNotEmpty(t, storeDevice.PrivateKey)
	assertNotEmpty(t, storeDevice.PublicKey)
}

func TestCreateSignatureDevice_ErrExists(t *testing.T) {
	db := &SignatureDeviceInMemoryDbStub{
		StoreFunc: func(device persistence.SignatureDevice) error {
			return ErrExists
		},
	}
	domain := NewSignatureDeviceDomain(db)

	_, err := domain.CreateSignatureDevice("550e8400-e29b-11d4-a716-446655440000", "ECC", "")

	assertEqual(t, ErrExists, err)
}

func TestReadSignatureDevice_Ok(t *testing.T) {
	db := &SignatureDeviceInMemoryDbStub{
		FindByIdFunc: func(key persistence.Id) (persistence.SignatureDevice, error) {
			return device1, nil
		},
	}
	domain := NewSignatureDeviceDomain(db)

	device, err := domain.ReadSignatureDevice("550e8400-e29b-11d4-a716-446655440000")

	assertEqual(t, nil, err)
	assertEqual(t, SignatureDevice{
		Id:               "550e8400-e29b-11d4-a716-446655440000",
		Algorithm:        "ECC",
		Label:            "device1",
		SignatureCounter: 0,
		LastSignature:    "NTUwZTg0MDAtZTI5Yi0xMWQ0LWE3MTYtNDQ2NjU1NDQwMDAw",
	}, device)
}

func TestReadSignatureDevice_ErrNotFound(t *testing.T) {
	db := &SignatureDeviceInMemoryDbStub{
		FindByIdFunc: func(key persistence.Id) (persistence.SignatureDevice, error) {
			return persistence.SignatureDevice{}, ErrNotFound
		},
	}
	domain := NewSignatureDeviceDomain(db)

	_, err := domain.ReadSignatureDevice("550e8400-e29b-11d4-a716-446655440000")

	assertEqual(t, ErrNotFound, err)
}

func TestSignTransaction_Ok(t *testing.T) {
	var newDevice persistence.SignatureDevice
	db := &SignatureDeviceInMemoryDbStub{
		FindByIdFunc: func(key persistence.Id) (persistence.SignatureDevice, error) {
			return device1, nil
		},
		CompareAndSwapFunc: func(old, new persistence.SignatureDevice) error {
			newDevice = new
			return nil
		},
	}
	domain := NewSignatureDeviceDomain(db)

	signature, err := domain.SignTransaction("550e8400-e29b-11d4-a716-446655440000", "test")

	assertEqual(t, nil, err)
	assertEqual(t, "0_test_NTUwZTg0MDAtZTI5Yi0xMWQ0LWE3MTYtNDQ2NjU1NDQwMDAw", signature.SignedData)
	assertEqual(t, signature.Signature, newDevice.LastSignature)
	assertEqual(t, 1, newDevice.SignatureCounter)
}

func TestSignTransaction_ErrNotFound(t *testing.T) {
	db := &SignatureDeviceInMemoryDbStub{
		FindByIdFunc: func(key persistence.Id) (persistence.SignatureDevice, error) {
			return persistence.SignatureDevice{}, ErrNotFound
		},
	}
	domain := NewSignatureDeviceDomain(db)

	_, err := domain.SignTransaction("550e8400-e29b-11d4-a716-446655440000", "test")

	assertEqual(t, ErrNotFound, err)
}

func TestReadSignatureDevices_Ok(t *testing.T) {
	db := &SignatureDeviceInMemoryDbStub{
		FindAllFunc: func() []persistence.SignatureDevice {
			return []persistence.SignatureDevice{device1}
		},
	}
	domain := NewSignatureDeviceDomain(db)

	devices := domain.ReadSignatureDevices()

	assertEqual(t, SignatureDevice{
		Id:               "550e8400-e29b-11d4-a716-446655440000",
		Algorithm:        "ECC",
		Label:            "device1",
		SignatureCounter: 0,
		LastSignature:    "NTUwZTg0MDAtZTI5Yi0xMWQ0LWE3MTYtNDQ2NjU1NDQwMDAw",
	}, devices[0])
}
