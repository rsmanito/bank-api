-- name: CreateUser :exec
INSERT INTO users (
  id, first_name, last_name, email, password
) VALUES ( $1, $2, $3, $4, $5);

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1
LIMIT 1;

-- name: GetUserById :one
SELECT * 
FROM users
WHERE id = $1
LIMIT 1;

-- name: SaveUserTokens :exec
INSERT INTO tokens (
  user_id, token, refresh_token
) VALUES ( $1, $2, $3 )
ON CONFLICT ( user_id )
DO UPDATE SET 
  token = $2,
  refresh_token = $3;

-- name: GetUserTokens :one
SELECT *
FROM tokens
WHERE user_id = $1;

-- name: GetUserCards :many
SELECT *
FROM cards
WHERE holder = $1;

-- name: CreateCard :exec
INSERT INTO cards (
  holder, number, title, type, currency
) VALUES ( $1, $2, $3, $4, $5 );

-- name: CardNumberExists :one
SELECT EXISTS(
  SELECT 1
  FROM cards
  WHERE number = $1
) as exists;
