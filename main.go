package main

import (
	"log"

	"github.com/rsmanito/bank-api/server"
	"github.com/rsmanito/bank-api/storage"
)

func main() {
	st := storage.New()
	s := server.New(st)

	go s.Run(":3000")

	log.Default().Println("Running on port 3000")
	select {}
}
