package api

import (
	"encoding/json"
	"net/http"

	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/gorilla/mux"
)

// Response is the generic API response container.
type Response struct {
	Data interface{} `json:"data"`
}

// ErrorResponse is the generic error API response container.
type ErrorResponse struct {
	Errors []string `json:"errors"`
}

// Server manages HTTP requests and dispatches them to the appropriate services.
type Server struct {
	listenAddress string
	domain        domain.ISignatureDeviceDomain
}

// NewServer is a factory to instantiate a new Server.
func NewServer(listenAddress string, domain domain.ISignatureDeviceDomain) *Server {
	return &Server{
		listenAddress: listenAddress,
		domain:        domain,
	}
}

// Run registers all HandlerFuncs for the existing HTTP routes and starts the Server.
func (s *Server) Run() error {
	r := mux.NewRouter()

	r.Handle("/api/v0/health", http.HandlerFunc(s.Health))
	r.Handle("/api/v0/devices", http.HandlerFunc(s.ReadSignatureDevices)).Methods("GET")
	r.Handle("/api/v0/devices", http.HandlerFunc(s.CreateSignatureDevice)).Methods("POST")
	r.Handle("/api/v0/devices/{id}", http.HandlerFunc(s.ReadSignatureDevice)).Methods("GET")
	r.Handle("/api/v0/devices/{id}:sign", http.HandlerFunc(s.SignTransaction)).Methods("POST")

	return http.ListenAndServe(s.listenAddress, r)
}

// WriteInternalError writes a default internal error message as an HTTP response.
func WriteInternalError(w http.ResponseWriter) {
	w.WriteHeader(http.StatusInternalServerError)
	w.Write([]byte(http.StatusText(http.StatusInternalServerError)))
}

// WriteErrorResponse takes an HTTP status code and a slice of errors
// and writes those as an HTTP error response in a structured format.
func WriteErrorResponse(w http.ResponseWriter, code int, errors []string) {
	w.WriteHeader(code)

	errorResponse := ErrorResponse{
		Errors: errors,
	}

	bytes, err := json.Marshal(errorResponse)
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}

// WriteAPIResponse takes an HTTP status code and a generic data struct
// and writes those as an HTTP response in a structured format.
func WriteAPIResponse(w http.ResponseWriter, code int, data interface{}) {
	w.WriteHeader(code)

	response := Response{
		Data: data,
	}

	bytes, err := json.MarshalIndent(response, "", "  ")
	if err != nil {
		WriteInternalError(w)
	}

	w.Write(bytes)
}
