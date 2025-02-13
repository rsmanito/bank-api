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
