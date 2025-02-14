package storage

import (
	"context"
	"database/sql"
	"embed"
	"log"

	"github.com/jackc/pgx/v5"
	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
	"github.com/rsmanito/bank-api/config"
	"github.com/rsmanito/bank-api/storage/postgres"
)

type Storage struct {
	*postgres.Queries
}

//go:embed migrations/*.sql
var embedMigrations embed.FS

func (s *Storage) Migrate(cfg *config.Config) {
	log.Default().Println("Migrating database")

	db, err := sql.Open(
		"postgres",
		cfg.DB_CONN_URL,
	)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("pgx"); err != nil {
		panic(err)
	}

	if err := goose.Up(db, "migrations"); err != nil {
		panic(err)
	}

	log.Default().Println("Database migrated")
}

func New(cfg *config.Config) *Storage {
	conn, err := pgx.Connect(
		context.Background(),
		cfg.DB_CONN_URL,
	)
	if err != nil {
		panic(err)
	}

	err = conn.Ping(context.Background())
	if err != nil {
		panic(err)
	}

	queries := postgres.New(conn)

	st := &Storage{queries}
	st.Migrate(cfg)

	return st
}
