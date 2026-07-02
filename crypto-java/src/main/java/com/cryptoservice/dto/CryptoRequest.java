package com.cryptoservice.dto;

public class CryptoRequest {

    private String documentName;
    private String documentType;
    private byte[] documentData;
    private boolean detached;

    public CryptoRequest(String documentName, String documentType, byte[] documentData) {
        this.documentName = documentName;
        this.documentType = documentType;
        this.documentData = documentData;
    }

    public CryptoRequest(String documentName, String documentType, byte[] documentData, boolean detached) {
        this.documentName = documentName;
        this.documentType = documentType;
        this.documentData = documentData;
        this.detached = detached;
    }

    public byte[] getDocumentData() {
        return documentData;
    }

    public void setDocumentData(byte[] documentData) {
        this.documentData = documentData;
    }

    public boolean isDetached() {
        return detached;
    }

    public void setDetached(boolean detached) {
        this.detached = detached;
    }

    public String getDocumentName() {
        return documentName;
    }

    public void setDocumentName(String documentName) {
        this.documentName = documentName;
    }

    public String getDocumentType() {
        return documentType;
    }

    public void setDocumentType(String documentType) {
        this.documentType = documentType;
    }
}
