package db

import (
	"database/sql"
	"embed"
	"fmt"

	_ "modernc.org/sqlite"
)

//go:embed scripts/schema.sql
var schemaFS embed.FS

func Init() (*sql.DB, error) {
	db, err := sql.Open("sqlite", "file::memory:?cache=shared")
	if err != nil {
		return nil, fmt.Errorf("ошибка открытия соединения: %w", err)
	}

	if err = db.Ping(); err != nil {
		db.Close()
		return nil, fmt.Errorf("ошибка пингования базы: %w", err)
	}

	schema, err := schemaFS.ReadFile("scripts/schema.sql")
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("ошибка чтения schema.sql: %w", err)
	}

	if _, err = db.Exec(string(schema)); err != nil {
		db.Close()
		return nil, fmt.Errorf("ошибка создания таблиц: %w", err)
	}

	return db, nil
}
