fmt:
	go fmt ./...

vet: fmt
	go vet ./...

run: vet
	air

sqlc:
	cd storage && sqlc generate
