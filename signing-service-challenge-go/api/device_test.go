package api

import (
	"bytes"
	"encoding/json"
	"errors"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
)

func assertEqual(t *testing.T, expected interface{}, actual interface{}) {
	if !reflect.DeepEqual(expected, actual) {
		t.Errorf("Expected %v, actual %v", expected, actual)
	}
}

func assertJSONEqual(t *testing.T, expected []byte, actual []byte) {
	var a, b interface{}
	_ = json.Unmarshal(expected, &a)
	_ = json.Unmarshal(actual, &b)
	assertEqual(t, a, b)
}

type SignatureDeviceDomainStub struct {
	CreateSignatureDeviceFunc func(id, algorithm, label string) (domain.SignatureDevice, error)
	ReadSignatureDeviceFunc   func(id string) (domain.SignatureDevice, error)
	SignTransactionFunc       func(id string, data string) (domain.Signature, error)
	ReadSignatureDevicesFunc  func() []domain.SignatureDevice
}

func (s *SignatureDeviceDomainStub) CreateSignatureDevice(id, algorithm, label string) (domain.SignatureDevice, error) {
	return s.CreateSignatureDeviceFunc(id, algorithm, label)
}

func (s *SignatureDeviceDomainStub) ReadSignatureDevice(id string) (domain.SignatureDevice, error) {
	return s.ReadSignatureDeviceFunc(id)
}

func (s *SignatureDeviceDomainStub) SignTransaction(id string, data string) (domain.Signature, error) {
	return s.SignTransactionFunc(id, data)
}

func (s *SignatureDeviceDomainStub) ReadSignatureDevices() []domain.SignatureDevice {
	return s.ReadSignatureDevicesFunc()
}

func TestCreateSignatureDevice_Ok(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		CreateSignatureDeviceFunc: func(id, algorithm, label string) (domain.SignatureDevice, error) {
			return domain.SignatureDevice{
				Id:               "550e8400-e29b-11d4-a716-446655440000",
				Algorithm:        "ECC",
				SignatureCounter: 0,
			}, nil
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices",
		bytes.NewReader([]byte(`{
			"id": "550e8400-e29b-11d4-a716-446655440000",
			"algorithm": "ECC"
		}`),
		))
	w := httptest.NewRecorder()
	s.CreateSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusCreated, resp.StatusCode)
	assertJSONEqual(t, body, []byte(`{
	  "data": {
		"id": "550e8400-e29b-11d4-a716-446655440000",
		"algorithm": "ECC",
		"signature_counter": 0
	  }
	}`))
}

func TestCreateSignatureDevice_ErrInvalidJSON(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices",
		bytes.NewReader([]byte(`{{`)),
	)
	w := httptest.NewRecorder()
	s.CreateSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusBadRequest, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
		"errors":["invalid json body"]
	}`), body)
}

func TestCreateSignatureDevice_ErrExists(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		CreateSignatureDeviceFunc: func(id, algorithm, label string) (domain.SignatureDevice, error) {
			return domain.SignatureDevice{}, domain.ErrExists
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices",
		bytes.NewReader([]byte(`{
			"id": "550e8400-e29b-11d4-a716-446655440000",
			"algorithm": "ECC"
		}`),
		))
	w := httptest.NewRecorder()
	s.CreateSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusConflict, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
		"errors":["already exists"]
	}`), body)
}

func TestCreateSignatureDevice_ErrInvalidUUID(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		CreateSignatureDeviceFunc: func(id, algorithm, label string) (domain.SignatureDevice, error) {
			return domain.SignatureDevice{}, domain.ErrInvalidUUID
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices",
		bytes.NewReader([]byte(`{
			"id": "550e8400-e29b-11d4-a716-446655440000",
			"algorithm": "ECC"
		}`),
		))
	w := httptest.NewRecorder()
	s.CreateSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusBadRequest, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
		"errors":["invalid uuid"]
	}`), body)
}

func TestCreateSignatureDevice_Err(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		CreateSignatureDeviceFunc: func(id, algorithm, label string) (domain.SignatureDevice, error) {
			return domain.SignatureDevice{}, errors.New("generic error")
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices",
		bytes.NewReader([]byte(`{
			"id": "550e8400-e29b-11d4-a716-446655440000",
			"algorithm": "ECC"
		}`),
		))
	w := httptest.NewRecorder()
	s.CreateSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusInternalServerError, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
		"errors":["Internal Server Error"]
	}`), body)
}

func TestReadSignatureDevice_Ok(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		ReadSignatureDeviceFunc: func(id string) (domain.SignatureDevice, error) {
			return domain.SignatureDevice{
				Id:               "550e8400-e29b-11d4-a716-446655440000",
				Algorithm:        "ECC",
				SignatureCounter: 0,
			}, nil
		},
	})
	req := httptest.NewRequest("GET", "/api/v0/devices/550e8400-e29b-11d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	s.ReadSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusOK, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "data": {
		"id": "550e8400-e29b-11d4-a716-446655440000",
		"algorithm": "ECC",
		"signature_counter": 0
	  }
	}`), body)
}

func TestReadSignatureDevice_ErrNotFound(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		ReadSignatureDeviceFunc: func(id string) (domain.SignatureDevice, error) {
			return domain.SignatureDevice{}, domain.ErrNotFound
		},
	})
	req := httptest.NewRequest("GET", "/api/v0/devices/550e8400-e29b-11d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	s.ReadSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusNotFound, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "errors":["not found"]
	}`), body)
}

func TestReadSignatureDevice_Err(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		ReadSignatureDeviceFunc: func(id string) (domain.SignatureDevice, error) {
			return domain.SignatureDevice{}, errors.New("generic error")
		},
	})
	req := httptest.NewRequest("GET", "/api/v0/devices/550e8400-e29b-11d4-a716-446655440000", nil)
	w := httptest.NewRecorder()
	s.ReadSignatureDevice(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusInternalServerError, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "errors":["Internal Server Error"]
	}`), body)
}

func TestSignTransaction_Ok(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		SignTransactionFunc: func(id string, data string) (domain.Signature, error) {
			return domain.Signature{
				Signature:  "jNpltKGS3268vNJxnKGx22bbmFoLXAiIQx7+RHntlszV2etE3sbs+f/aohtG5Lc7zpWulhuTamy3+SqZFbTGbQ==",
				SignedData: "0_test_NTUwZTg0MDAtZTI5Yi0xMWQ0LWE3MTYtNDQ2NjU1NDQwMDAw",
			}, nil
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices/550e8400-e29b-11d4-a716-446655440000:sign",
		bytes.NewReader([]byte(`{
			"data_to_be_signed": "test"
		}`),
		))
	w := httptest.NewRecorder()
	s.SignTransaction(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusOK, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "data": {
		"signature": "jNpltKGS3268vNJxnKGx22bbmFoLXAiIQx7+RHntlszV2etE3sbs+f/aohtG5Lc7zpWulhuTamy3+SqZFbTGbQ==",
		"signed_data": "0_test_NTUwZTg0MDAtZTI5Yi0xMWQ0LWE3MTYtNDQ2NjU1NDQwMDAw"
	  }
	}`), body)
}

func TestSignTransaction_ErrInvalidJSON(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices/550e8400-e29b-11d4-a716-446655440000:sign",
		bytes.NewReader([]byte(`{{`)),
	)
	w := httptest.NewRecorder()
	s.SignTransaction(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusBadRequest, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "errors":["invalid json body"]
	}`), body)
}

func TestSignTransaction_ErrModified(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		SignTransactionFunc: func(id string, data string) (domain.Signature, error) {
			return domain.Signature{}, domain.ErrModified
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices/550e8400-e29b-11d4-a716-446655440000:sign",
		bytes.NewReader([]byte(`{
			"data_to_be_signed": "data"
		}`),
		))
	w := httptest.NewRecorder()
	s.SignTransaction(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusConflict, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "errors":["concurrent modifications"]
	}`), body)
}

func TestSignTransaction_ErrNotFound(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		SignTransactionFunc: func(id string, data string) (domain.Signature, error) {
			return domain.Signature{}, domain.ErrNotFound
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices/550e8400-e29b-11d4-a716-446655440000:sign",
		bytes.NewReader([]byte(`{
			"data_to_be_signed": "data"
		}`),
		))
	w := httptest.NewRecorder()
	s.SignTransaction(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusNotFound, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "errors":["not found"]
	}`), body)
}

func TestSignTransaction_Err(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		SignTransactionFunc: func(id string, data string) (domain.Signature, error) {
			return domain.Signature{}, errors.New("generic error")
		},
	})
	req := httptest.NewRequest(
		"POST",
		"/api/v0/devices/550e8400-e29b-11d4-a716-446655440000:sign",
		bytes.NewReader([]byte(`{
			"data_to_be_signed": "data"
		}`),
		))
	w := httptest.NewRecorder()
	s.SignTransaction(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusInternalServerError, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
	  "errors":["Internal Server Error"]
	}`), body)
}

func TestReadSignatureDevices_Ok(t *testing.T) {
	s := NewServer("", &SignatureDeviceDomainStub{
		ReadSignatureDevicesFunc: func() []domain.SignatureDevice {
			return []domain.SignatureDevice{
				{
					Id:               "550e8400-e29b-11d4-a716-446655440000",
					Algorithm:        "ECC",
					SignatureCounter: 0,
				},
				{
					Id:               "550e8400-e29b-11d4-a716-446655440001",
					Algorithm:        "RSA",
					SignatureCounter: 1,
				},
			}
		},
	})
	req := httptest.NewRequest("GET", "/api/v0/devices", nil)
	w := httptest.NewRecorder()
	s.ReadSignatureDevices(w, req)

	resp := w.Result()
	body, _ := io.ReadAll(resp.Body)

	assertEqual(t, http.StatusOK, resp.StatusCode)
	assertJSONEqual(t, []byte(`{
		"data": [
			{
				"id": "550e8400-e29b-11d4-a716-446655440000",
				"algorithm": "ECC",
				"signature_counter": 0
			},
			{
				"id": "550e8400-e29b-11d4-a716-446655440001",
				"algorithm": "RSA",
				"signature_counter": 1
			}
		]
	}`), body)
}
