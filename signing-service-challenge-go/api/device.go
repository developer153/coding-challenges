package api

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/gorilla/mux"
)

type CreateSignatureDeviceRequest struct {
	Id        string `json:"id"`
	Algorithm string `json:"algorithm"`
	Label     string `json:"label,omitempty"`
}

type CreateSignatureDeviceResponse struct {
	Id               string `json:"id"`
	Algorithm        string `json:"algorithm"`
	Label            string `json:"label,omitempty"`
	SignatureCounter int    `json:"signature_counter"`
}

func (s *Server) CreateSignatureDevice(response http.ResponseWriter, request *http.Request) {
	var createRequest CreateSignatureDeviceRequest
	if err := json.NewDecoder(request.Body).Decode(&createRequest); err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"invalid json body",
		})
		return
	}

	device, err := s.domain.CreateSignatureDevice(createRequest.Id, createRequest.Algorithm, createRequest.Label)
	if err != nil {
		if errors.Is(err, domain.ErrExists) {
			WriteErrorResponse(response, http.StatusConflict, []string{
				err.Error(),
			})
			return
		}
		if errors.Is(err, domain.ErrInvalidUUID) || errors.Is(err, domain.ErrInvalidAlgorithm) {
			WriteErrorResponse(response, http.StatusBadRequest, []string{
				err.Error(),
			})
			return
		}
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	createResponse := CreateSignatureDeviceResponse{
		Id:               device.Id,
		Label:            device.Label,
		Algorithm:        device.Algorithm,
		SignatureCounter: device.SignatureCounter,
	}
	WriteAPIResponse(response, http.StatusCreated, createResponse)
}

func (s *Server) ReadSignatureDevice(response http.ResponseWriter, request *http.Request) {
	vars := mux.Vars(request)
	id := vars["id"]

	device, err := s.domain.ReadSignatureDevice(id)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			WriteErrorResponse(response, http.StatusNotFound, []string{
				err.Error(),
			})
			return
		}
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	readResponse := CreateSignatureDeviceResponse{
		Id:               device.Id,
		Label:            device.Label,
		Algorithm:        device.Algorithm,
		SignatureCounter: device.SignatureCounter,
	}
	WriteAPIResponse(response, http.StatusOK, readResponse)
}

func (s *Server) ReadSignatureDevices(response http.ResponseWriter, _ *http.Request) {
	devices := s.domain.ReadSignatureDevices()
	readResponse := make([]CreateSignatureDeviceResponse, 0)
	for _, device := range devices {
		readResponse = append(readResponse, CreateSignatureDeviceResponse{
			Id:               device.Id,
			Label:            device.Label,
			Algorithm:        device.Algorithm,
			SignatureCounter: device.SignatureCounter,
		})
	}
	WriteAPIResponse(response, http.StatusOK, readResponse)
}

type SignTransactionRequest struct {
	DataToBeSigned string `json:"data_to_be_signed"`
}

type SignTransactionResponse struct {
	Signature  string `json:"signature"`
	SignedData string `json:"signed_data"`
}

func (s *Server) SignTransaction(response http.ResponseWriter, request *http.Request) {
	var signRequest SignTransactionRequest
	if err := json.NewDecoder(request.Body).Decode(&signRequest); err != nil {
		WriteErrorResponse(response, http.StatusBadRequest, []string{
			"invalid json body",
		})
		return
	}

	vars := mux.Vars(request)
	id := vars["id"]

	signature, err := s.domain.SignTransaction(id, signRequest.DataToBeSigned)
	if err != nil {
		if errors.Is(err, domain.ErrNotFound) {
			WriteErrorResponse(response, http.StatusNotFound, []string{
				err.Error(),
			})
			return
		}
		if errors.Is(err, domain.ErrModified) {
			WriteErrorResponse(response, http.StatusConflict, []string{
				err.Error(),
			})
			return
		}
		WriteErrorResponse(response, http.StatusInternalServerError, []string{
			http.StatusText(http.StatusInternalServerError),
		})
		return
	}

	signResponse := SignTransactionResponse{
		Signature:  signature.Signature,
		SignedData: signature.SignedData,
	}
	WriteAPIResponse(response, http.StatusOK, signResponse)
}
