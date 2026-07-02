package com.cryptoservice.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;

public class CryptedDocument {

    @JsonProperty("id")
    private Long id;

    @JsonProperty("data")
    private byte[] data;

    @JsonProperty("size")
    private Long size;

    @JsonProperty("document_id")
    private Long documentId;

    @JsonProperty("document_name")
    private String documentName;

    @JsonProperty("operation_type")
    private String operationType;

    @JsonProperty("created_at")
    private OffsetDateTime createdAt;

    public CryptedDocument() {
    }

    public CryptedDocument(Long documentId, String documentName, String operationType, byte[] data) {
        this.documentId = documentId;
        this.documentName = documentName;
        this.operationType = operationType;
        this.data = data;
        this.size = (long) (data != null ? data.length : 0);
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public Long getDocumentId() {
        return documentId;
    }

    public void setDocumentId(Long documentId) {
        this.documentId = documentId;
    }

    public String getOperationType() {
        return operationType;
    }

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    public byte[] getData() {
        return data;
    }

    public void setData(byte[] data) {
        this.data = data;
        this.size = (long) (data != null ? data.length : 0);
    }

    public Long getSize() {
        return size;
    }

    public void setSize(Long size) {
        this.size = size;
    }

    public OffsetDateTime getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(OffsetDateTime createdAt) {
        this.createdAt = createdAt;
    }

    public String getDocumentName() {
        return documentName;
    }

    public void setDocumentName(String documentName) {
        this.documentName = documentName;
    }
}
