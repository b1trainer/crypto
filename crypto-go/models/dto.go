package models

type ErrorResponse struct {
	Error string `json:"error"`
}

type CryptoRequest struct {
	DocumentName string `json:"document_name"`
	DocumentType string `json:"document_type"`
	DocumentData string `json:"document_data"`
	Detached     bool   `json:"detached"`
}

type CryptoResponse struct {
	Result    interface{} `json:"result"`
	Operation string      `json:"operation"`
}
