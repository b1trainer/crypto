package db

import (
	"crypto-go/models"
	"database/sql"
	"fmt"
	"log"
	"time"
)

//----------------------------------------------------------------------------------------------------------------------
// Operations with uploaded, non crypted documents
//----------------------------------------------------------------------------------------------------------------------

func SaveDoc(db *sql.DB, doc *models.Document) (int64, error) {
	query := `INSERT INTO documents (name, content_type, data, size) VALUES (?, ?, ?, ?)`
	result, err := db.Exec(query, doc.Name, doc.ContentType, doc.Data, int64(len(doc.Data)))
	if err != nil {
		return 0, fmt.Errorf("failed to save document: %w", err)
	}
	id, err := result.LastInsertId()
	if err != nil {
		return 0, err
	}
	log.Printf("Document saved with id=%d", id)
	return id, nil
}

func GetDoc(db *sql.DB, name string) (*models.Document, error) {
	query := `SELECT * FROM documents WHERE name = ?`
	row := db.QueryRow(query, name)

	var doc models.Document
	var createdAt string

	if err := row.Scan(&doc.ID, &doc.Name, &doc.ContentType, &doc.Data, &doc.Size, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("document with name %s not found", name)
		}
		return nil, fmt.Errorf("failed to retrieve document: %w", err)
	}
	if t, err := time.Parse("2006-01-02 15:04:05", createdAt); err == nil {
		doc.CreatedAt = t
	}
	return &doc, nil
}

//----------------------------------------------------------------------------------------------------------------------
// Operations with processed, (en)crypted documents
//----------------------------------------------------------------------------------------------------------------------

func SaveCrypted(db *sql.DB, result *models.CryptedDoc) (int64, error) {
	query := `INSERT INTO cryptedDocuments (document_id, document_name, operation_type, data, size) VALUES (?, ?, ?, ?, ?)`
	res, err := db.Exec(query, result.DocumentID, result.DocumentName, result.OperationType, result.Data, int64(len(result.Data)))
	if err != nil {
		return 0, fmt.Errorf("failed to save result: %w", err)
	}
	id, err := res.LastInsertId()
	if err != nil {
		return 0, err
	}
	log.Printf("Result saved with id=%d", id)
	return id, nil
}

func GetCrypted(db *sql.DB, name string) (*models.CryptedDoc, error) {
	query := `SELECT * FROM cryptedDocuments WHERE document_name = ? ORDER BY created_at DESC LIMIT 1`
	row := db.QueryRow(query, name)

	var doc models.CryptedDoc
	var createdAt string

	if err := row.Scan(&doc.ID, &doc.DocumentID, &doc.DocumentName, &doc.OperationType, &doc.Data, &doc.Size, &createdAt); err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("crypted document with name %q not found", name)
		}
		return nil, fmt.Errorf("failed to retrieve crypted document: %w", err)
	}
	if t, err := time.Parse("2006-01-02 15:04:05", createdAt); err == nil {
		doc.CreatedAt = t
	}
	return &doc, nil
}

//----------------------------------------------------------------------------------------------------------------------
// Operations with logs
//----------------------------------------------------------------------------------------------------------------------

func SaveLog(db *sql.DB, logEntry *models.OperationLog) error {
	query := `INSERT INTO operations_log (operation_type, status, details, duration_ms) VALUES (?, ?, ?, ?)`
	if _, err := db.Exec(query, logEntry.OperationType, logEntry.Status, logEntry.Details, logEntry.DurationMs); err != nil {
		return fmt.Errorf("failed to save operation log: %w", err)
	}
	return nil
}

func GetAllLogs(db *sql.DB) ([]models.OperationLog, error) {
	query := `SELECT * FROM operations_log ORDER BY created_at DESC`
	rows, err := db.Query(query)
	if err != nil {
		return nil, fmt.Errorf("failed to query operation logs: %w", err)
	}
	defer rows.Close()

	logs := make([]models.OperationLog, 0)
	var operationLog models.OperationLog
	var detailsSQL sql.NullString
	var createdAt string

	for rows.Next() {
		operationLog = models.OperationLog{}
		if err := rows.Scan(&operationLog.ID, &operationLog.OperationType, &operationLog.Status, &detailsSQL, &operationLog.DurationMs, &createdAt); err != nil {
			return nil, fmt.Errorf("failed to scan log row: %w", err)
		}
		if detailsSQL.Valid {
			operationLog.Details = detailsSQL.String
		}
		if t, err := time.Parse("2006-01-02 15:04:05", createdAt); err == nil {
			operationLog.CreatedAt = t
		}
		logs = append(logs, operationLog)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating logs: %w", err)
	}
	return logs, nil
}
