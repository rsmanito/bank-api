package config

import "github.com/caarlos0/env/v11"

type Config struct {
	Port            string `env:"PORT" envDefault:":3000"`
	JWT_SIGNING_KEY string `env:"JWT_SIGNING_KEY" envDefault:"supersecret"`
	DB_CONN_URL     string `env:"DB_CONNECTION_URL" envDefault:"postgres://postgres:postgres@localhost:5432/postgres?sslmode=disable"`
}

func Load() *Config {
	var cfg Config

	err := env.Parse(&cfg)
	if err != nil {
		panic(err)
	}

	return &cfg
}
