package persistence

import (
	"errors"
	"sync"
)

type Id string

type ISignatureDeviceDb interface {
	Store(device SignatureDevice) error
	FindById(id Id) (SignatureDevice, error)
	CompareAndSwap(old, new SignatureDevice) error
	FindAll() []SignatureDevice
}

type SignatureDevice struct {
	Id               Id
	Algorithm        string
	Label            string
	PublicKey        []byte
	PrivateKey       []byte
	SignatureCounter int
	LastSignature    string
}

type InMemorySignatureDeviceDb struct {
	mu    sync.RWMutex
	store map[Id]SignatureDevice
}

var (
	ErrExists   = errors.New("already exists")
	ErrNotFound = errors.New("not found")
	ErrModified = errors.New("concurrent modifications")
)

func NewSignatureDeviceDb() ISignatureDeviceDb {
	return &InMemorySignatureDeviceDb{
		store: make(map[Id]SignatureDevice),
	}
}

func (db *InMemorySignatureDeviceDb) Store(device SignatureDevice) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	if _, exists := db.store[device.Id]; exists {
		return ErrExists
	}
	db.store[device.Id] = device
	return nil
}

func (db *InMemorySignatureDeviceDb) FindById(key Id) (SignatureDevice, error) {
	db.mu.RLock()
	defer db.mu.RUnlock()
	device, exists := db.store[key]
	if !exists {
		return SignatureDevice{}, ErrNotFound
	}
	return device, nil
}

func (db *InMemorySignatureDeviceDb) CompareAndSwap(old, new SignatureDevice) error {
	db.mu.Lock()
	defer db.mu.Unlock()
	record, exists := db.store[new.Id]
	if !exists {
		return ErrNotFound
	}
	if record.SignatureCounter != old.SignatureCounter {
		return ErrModified
	}
	db.store[new.Id] = new
	return nil
}

func (db *InMemorySignatureDeviceDb) FindAll() []SignatureDevice {
	db.mu.RLock()
	defer db.mu.RUnlock()
	values := make([]SignatureDevice, 0)
	for key := range db.store {
		values = append(values, db.store[key])
	}
	return values
}
