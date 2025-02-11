-- +goose Up
-- +goose StatementBegin
ALTER TABLE tokens
  ADD COLUMN refresh_token BYTEA NOT NULL;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
ALTER TABLE tokens
  DROP COLUMN refresh_token;
-- +goose StatementEnd
