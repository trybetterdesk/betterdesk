package db

import (
	"database/sql"
	"errors"

	"github.com/jackc/pgx/v5"
)

// IsNoRows reports whether err is the "no row" of either backend, as a
// Get method returns it for a row that does not exist.
func IsNoRows(err error) bool {
	return errors.Is(err, sql.ErrNoRows) || errors.Is(err, pgx.ErrNoRows)
}
