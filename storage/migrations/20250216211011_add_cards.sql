-- +goose Up
-- +goose StatementBegin
CREATE TYPE card_type AS ENUM (
  'DEBIT',
  'CREDIT'
);

CREATE TABLE IF NOT EXISTS cards (
  id BIGSERIAL PRIMARY KEY,
  holder UUID NOT NULL REFERENCES users(id),
  number TEXT NOT NULL,
  title TEXT,
  balance NUMERIC(10,2) NOT NULL DEFAULT 0,
  type card_type NOT NULL,
  currency VARCHAR(3) NOT NULL
);
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
DELETE TABLE IF EXISTS cards;
DROP TYPE card_type;
-- +goose StatementEnd
