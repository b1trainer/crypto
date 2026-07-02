package handlers

import (
	"crypto-go/config"
	"crypto-go/crypto"
	"crypto-go/db"
	"crypto-go/models"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/gabriel-vasile/mimetype"
)

type Handler struct {
	db         *sql.DB
	sigService *crypto.SignatureService
	encService *crypto.EncryptionService
	certs      *config.Certs
}

func NewHandler(database *sql.DB, sigService *crypto.SignatureService, encService *crypto.EncryptionService, certs *config.Certs) (*Handler, error) {
	return &Handler{
		db:         database,
		sigService: sigService,
		encService: encService,
		certs:      certs,
	}, nil
}

func (h *Handler) Hash(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	doc, err := h.readRequest(r)
	if err != nil {
		writeErrToOutput(w, err)
		h.logError("HASH_SHA256", err, start)
		return
	}

	docID, err := db.SaveDoc(h.db, doc)
	if err != nil {
		writeErrToOutput(w, err)
		h.logError("HASH_SHA256", err, start)
		return
	}

	hash := sha256.Sum256(doc.Data)
	hashValue := hex.EncodeToString(hash[:])

	db.SaveCrypted(h.db, &models.CryptedDoc{
		DocumentID:    docID,
		DocumentName:  doc.Name,
		OperationType: "HASH_SHA256",
		Data:          []byte(hashValue),
	})

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.CryptoResponse{
		Result:    hashValue,
		Operation: "HASH_SHA256",
	})

	h.logSuccess("HASH_SHA256", "HASHED: "+doc.Name, start)
}

func (h *Handler) Sign(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	doc, err := h.readRequest(r)
	if err != nil {
		h.logError("SIGN", err, start)
		writeErrToOutput(w, err)
		return
	}

	docID, err := db.SaveDoc(h.db, doc)
	if err != nil {
		h.logError("SIGN", err, start)
		writeErrToOutput(w, err)
		return
	}

	signed, err := h.sigService.Sign(doc.Data, r.URL.Query().Get("attached") == "true")
	if err != nil {
		h.logError("SIGN", err, start)
		writeErrToOutput(w, err)
		return
	}

	db.SaveCrypted(h.db, &models.CryptedDoc{
		DocumentID:    docID,
		DocumentName:  doc.Name,
		OperationType: "SIGN",
		Data:          signed,
	})

	w.Header().Set("Content-Type", "application/pkcs7-signature")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s%s\"", doc.Name, ".p7s"))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(signed)))

	if _, err := w.Write(signed); err != nil {
		h.logError("SIGN", err, start)
		return
	}

	h.logSuccess("SIGN", "SIGNED: "+doc.Name, start)
}

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	doc, err := h.readRequest(r)
	if err != nil {
		h.logError("VERIFY", err, start)
		writeErrToOutput(w, err)
		return
	}

	crypted, err := db.GetCrypted(h.db, doc.Name)
	if err != nil {
		h.logError("VERIFY", err, start)
		writeErrToOutput(w, err)
		return
	}

	verified, err := h.sigService.Verify(doc.Data, crypted.Data)
	if err != nil {
		h.logError("VERIFY", err, start)
		writeErrToOutput(w, err)
		return
	}

	status := "SUCCESS"
	if verified == false {
		status = "INVALID"
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.CryptoResponse{Result: status, Operation: "VERIFY"})

	h.logSuccess("VERIFY", "VERIFIED: "+doc.Name, start)
}

func (h *Handler) Encrypt(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	doc, err := h.readRequest(r)
	if err != nil {
		h.logError("ENCRYPT", err, start)
		writeErrToOutput(w, err)
		return
	}

	docID, err := db.SaveDoc(h.db, doc)

	if err != nil {
		h.logError("ENCRYPT", err, start)
		writeErrToOutput(w, err)
		return
	}

	encrypted, err := h.encService.Encrypt(doc.Data)
	if err != nil {
		h.logError("ENCRYPT", err, start)
		writeErrToOutput(w, err)
		return
	}

	db.SaveCrypted(h.db, &models.CryptedDoc{
		DocumentID:    docID,
		DocumentName:  doc.Name,
		OperationType: "ENCRYPT",
		Data:          encrypted,
	})

	w.Header().Set("Content-Type", "application/pkcs7-mime; smime-type=enveloped-data")
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s%s\"", doc.Name, ".p7m"))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(encrypted)))

	if _, err := w.Write(encrypted); err != nil {
		h.logError("ENCRYPT", err, start)
		return
	}

	h.logSuccess("ENCRYPT", "ENCRYPTED: "+doc.Name, start)
}

func (h *Handler) Decrypt(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	crypted, err := h.readRequest(r)
	if err != nil {
		h.logError("DECRYPT", err, start)
		writeErrToOutput(w, err)
		return
	}

	decrypted, err := h.encService.Decrypt(crypted.Data)
	if err != nil {
		h.logError("DECRYPT", err, start)
		writeErrToOutput(w, err)
		return
	}

	original, err := db.GetDoc(h.db, strings.TrimSuffix(crypted.Name, ".p7m"))

	w.Header().Set("Content-Type", original.ContentType)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"", original.Name))
	w.Header().Set("Content-Length", fmt.Sprintf("%d", len(decrypted)))

	if _, err := w.Write(decrypted); err != nil {
		h.logError("DECRYPT", err, start)
		return
	}

	h.logSuccess("DECRYPT", "DECRYPTED: "+crypted.Name, start)
}

func (h *Handler) Operations(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	logs, err := db.GetAllLogs(h.db)
	if err != nil {
		h.logError("OPERATIONS", err, start)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(models.CryptoResponse{
		Result:    logs,
		Operation: "OPERATIONS",
	})
}

func (h *Handler) logSuccess(op string, details string, start time.Time) {
	if err := db.SaveLog(h.db, &models.OperationLog{
		OperationType: op,
		Status:        "SUCCESS",
		DurationMs:    time.Since(start).Milliseconds(),
		Details:       details,
		CreatedAt:     time.Now(),
	}); err != nil {
		log.Printf("ошибка логирования в базу данных: %v", err)
	}
}

func (h *Handler) logError(op string, e error, start time.Time) {
	if err := db.SaveLog(h.db, &models.OperationLog{
		OperationType: op,
		Status:        "ERROR",
		DurationMs:    time.Since(start).Milliseconds(),
		Details:       e.Error(),
		CreatedAt:     time.Now(),
	}); err != nil {
		log.Printf("ошибка логирования в базу данных: %v", err)
	}
}

func (h *Handler) readRequest(r *http.Request) (*models.Document, error) {
	if err := r.ParseMultipartForm(10 << 20); err != nil {
		return nil, err
	}

	file, header, err := r.FormFile("file")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}

	mime := mimetype.Detect(data)

	return &models.Document{
		Name:        header.Filename,
		ContentType: mime.String(),
		Data:        data,
	}, nil
}

func writeErrToOutput(w http.ResponseWriter, err error) {
	log.Printf("Handle error: %v", err)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(models.ErrorResponse{Error: err.Error()})
	return
}
