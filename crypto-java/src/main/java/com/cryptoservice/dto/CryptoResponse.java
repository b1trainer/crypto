package com.cryptoservice.dto;

import com.fasterxml.jackson.annotation.JsonProperty;

public class CryptoResponse {

    @JsonProperty("result")
    private String result;

    @JsonProperty("operation")
    private String operation;

    @JsonProperty("content_type")
    private String contentType;

    public CryptoResponse(String result, String operation) {
        this.result = result;
        this.operation = operation;
    }

    public CryptoResponse(String result, String operation, String contentType) {
        this.result = result;
        this.operation = operation;
        this.contentType = contentType;
    }

    public String getResult() {
        return result;
    }

    public void setResult(String result) {
        this.result = result;
    }

    public String getOperation() {
        return operation;
    }

    public void setOperation(String operation) {
        this.operation = operation;
    }

    public String getContentType() {
        return contentType;
    }

    public void setContentType(String contentType) {
        this.contentType = contentType;
    }
}
