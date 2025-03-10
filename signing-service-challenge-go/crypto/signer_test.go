package crypto

import (
	"encoding/base64"
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, expected any, actual any) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected %v, actual %v", expected, actual)
	}
}

var privateKeyEcc = `-----BEGIN PRIVATE_KEY-----
MIGkAgEBBDA10Qv12By0KByh0aaUZCmcwCSdhkMecHgRoYY3U2iiTmR4QU2iQbD6
IoeIHX10dgWgBwYFK4EEACKhZANiAASpKAp5IJCe//Maazpo9NAvChtA9nN1tENS
UJRJlf/uzPLYkkyjXVnYctQgteqTpNvtwk1eUNlE66yoC5LexPyjPJ8xpxSD+pu/
CyjmsnZywGVS42qb2Up3nMdYvgKMiBA=
-----END PRIVATE_KEY-----`

var privateKeyRsa = `-----BEGIN RSA_PRIVATE_KEY-----
MIIBOgIBAAJBAMubQX2f5zNDJrihXSBXXhUoYMz5VzXtV1ftbTENrOjzJWMHaYsi
VFiVXy5C7VkNOUO5mYgirtmn1XS/tyMpu3UCAwEAAQJABvHRYV2Liei9G121oB1w
F2dR1evzQ42dhbboGzI3jEJ0kRcjW2mLDZyBxkP9DOvHaSJ1SzCnE82JIhVF5jt/
wQIhAPJ34++VHU6zTA+GBT9gjJGLXTvXvv1nLOr/xA30T0j9AiEA1vgm3GON8Jf5
v7nnorgyloNjpX90nLRMsYs7CHKRYdkCIE6tnKcXieUJxTqcUIOaPsLTqDNM9Mqh
ei/fQq0Mg9W5AiEAwzQNXb1NK7dlQ3NV4s2uqjxfJO5K/u0+Y05R6cbXO2kCIC0f
2RoOmHnPIJAMxygHtGbD7bOGnT0SsN1TyZxB5cxl
-----END RSA_PRIVATE_KEY-----`

func TestNewSigner_OkECC(t *testing.T) {
	_, err := NewSigner("ECC", []byte(privateKeyEcc))

	assertEqual(t, nil, err)
}

func TestNewSigner_ErrDecodeECC(t *testing.T) {
	_, err := NewSigner("ECC", []byte(privateKeyRsa))

	assertEqual(t, ErrDecode, err)
}

func TestNewSigner_OkRSA(t *testing.T) {
	_, err := NewSigner("RSA", []byte(privateKeyRsa))

	assertEqual(t, nil, err)
}

func TestNewSigner_ErrDecodeRSA(t *testing.T) {
	_, err := NewSigner("RSA", []byte(privateKeyEcc))

	assertEqual(t, ErrDecode, err)
}

func TestNewSigner_ErrInvalidAlgorithm(t *testing.T) {
	_, err := NewSigner("ED25519", []byte(""))

	assertEqual(t, ErrInvalidAlgorithm, err)
}

func TestSign_OkRSA(t *testing.T) {
	signer, _ := NewSigner("RSA", []byte(privateKeyRsa))

	signedData, err := signer.Sign([]byte("data"))

	base64SignedData, _ := base64.StdEncoding.DecodeString("Chfz/KNiZMY+eXM9D9jj/Ge5bx1fgEQbCMkuENwrryPwPdh62ZF7qvBpWOMsoPpoy/n/Ft+g6h2TIy3/7EwIlw==")
	assertEqual(t, nil, err)
	assertEqual(t, base64SignedData, signedData)
}
