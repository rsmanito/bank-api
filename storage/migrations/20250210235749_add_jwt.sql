-- +goose Up
-- +goose StatementBegin
CREATE TABLE IF NOT EXISTS tokens (
  user_id UUID PRIMARY KEY REFERENCES users(id),
  token BYTEA NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE TABLE IF EXISTS tokens CASCADE;
-- +goose StatementEnd
