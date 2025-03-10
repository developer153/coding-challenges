package main

import (
	"github.com/fiskaly/coding-challenges/signing-service-challenge/api"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/domain"
	"github.com/fiskaly/coding-challenges/signing-service-challenge/persistence"
	"log"
)

const (
	ListenAddress = ":8080"
)

func main() {
	db := persistence.NewSignatureDeviceDb()
	server := api.NewServer(ListenAddress, domain.NewSignatureDeviceDomain(db))

	if err := server.Run(); err != nil {
		log.Fatal("Could not start server on ", ListenAddress)
	}
}
