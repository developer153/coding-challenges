package persistence

import (
	"reflect"
	"testing"
)

var device1 = SignatureDevice{
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

func assertEqual(t *testing.T, expected any, actual any) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected %v, actual %v", expected, actual)
	}
}

func TestStore_Ok(t *testing.T) {
	db := NewSignatureDeviceDb()

	err := db.Store(device1)

	assertEqual(t, nil, err)
	device, _ := db.FindById(device1.Id)
	assertEqual(t, device1, device)
}

func TestStore_ErrExists(t *testing.T) {
	db := NewSignatureDeviceDb()
	_ = db.Store(device1)

	err := db.Store(device1)

	assertEqual(t, ErrExists, err)
}

func TestFindById_Ok(t *testing.T) {
	db := NewSignatureDeviceDb()
	_ = db.Store(device1)

	device, err := db.FindById(device1.Id)

	assertEqual(t, nil, err)
	assertEqual(t, device1, device)
}

func TestFindById_ErrNotFound(t *testing.T) {
	db := NewSignatureDeviceDb()

	device, err := db.FindById(device1.Id)

	assertEqual(t, ErrNotFound, err)
	assertEqual(t, SignatureDevice{}, device)
}

func TestCompareAndSwap_Ok(t *testing.T) {
	db := NewSignatureDeviceDb()
	_ = db.Store(device1)
	device2 := SignatureDevice{
		Id:               device1.Id,
		Algorithm:        device1.Algorithm,
		Label:            device1.Label,
		PublicKey:        device1.PublicKey,
		PrivateKey:       device1.PrivateKey,
		SignatureCounter: device1.SignatureCounter + 1,
		LastSignature:    device1.LastSignature,
	}

	err := db.CompareAndSwap(device1, device2)
	device, _ := db.FindById(device1.Id)

	assertEqual(t, nil, err)
	assertEqual(t, device2, device)
}

func TestCompareAndSwap_ErrNotFound(t *testing.T) {
	db := NewSignatureDeviceDb()

	err := db.CompareAndSwap(device1, device1)

	assertEqual(t, ErrNotFound, err)
}

func TestCompareAndSwap_ErrModified(t *testing.T) {
	db := NewSignatureDeviceDb()
	device2 := SignatureDevice{
		SignatureCounter: device1.SignatureCounter + 1,
	}
	_ = db.Store(device2)
	device3 := SignatureDevice{
		SignatureCounter: device2.SignatureCounter + 1,
	}

	err := db.CompareAndSwap(device1, device3)

	assertEqual(t, ErrModified, err)
}

func TestFindAll_Ok(t *testing.T) {
	db := NewSignatureDeviceDb()
	_ = db.Store(device1)

	devices := db.FindAll()

	assertEqual(t, device1, devices[0])
}

func TestFindAll_OkEmpty(t *testing.T) {
	db := NewSignatureDeviceDb()

	device := db.FindAll()

	assertEqual(t, []SignatureDevice{}, device)
}
