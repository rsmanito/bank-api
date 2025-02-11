-- name: CreateUser :exec
INSERT INTO users (
  id, first_name, last_name, email, password
) VALUES ( $1, $2, $3, $4, $5);

-- name: GetUserByEmail :one
SELECT *
FROM users
WHERE email = $1
LIMIT 1;

-- name: SaveUserToken :exec
INSERT INTO tokens (
  user_id, token
) VALUES ( $1, $2 )
ON CONFLICT ( user_id )
DO UPDATE
SET token = $2;
