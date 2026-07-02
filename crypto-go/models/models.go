package models

import "time"

type OperationLog struct {
	ID            int64     `json:"id"`
	OperationType string    `json:"operation_type"`
	Status        string    `json:"status"`
	Details       string    `json:"details"`
	DurationMs    int64     `json:"duration_ms"`
	CreatedAt     time.Time `json:"created_at"`
}

type Document struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	ContentType string    `json:"content_type"`
	Data        []byte    `json:"data"`
	Size        int64     `json:"size"`
	CreatedAt   time.Time `json:"created_at"`
}

type CryptedDoc struct {
	ID            int64     `json:"id"`
	DocumentID    int64     `json:"document_id"`
	DocumentName  string    `json:"document_name"`
	OperationType string    `json:"operation_type"`
	Data          []byte    `json:"data"`
	Size          int64     `json:"size"`
	CreatedAt     time.Time `json:"created_at"`
}
