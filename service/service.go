package service

import "github.com/rsmanito/bank-api/storage"

type Service struct {
	st *storage.Storage // TODO: move to interface
}

// New returns a new Service.
func New(st *storage.Storage) *Service {
	return &Service{
		st: st,
	}
}
