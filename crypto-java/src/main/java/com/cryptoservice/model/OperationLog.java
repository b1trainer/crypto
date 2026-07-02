package com.cryptoservice.model;

import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.OffsetDateTime;

public class OperationLog {

    @JsonProperty("id")
    private Long id;

    @JsonProperty("operation_type")
    private String operationType;

    @JsonProperty("status")
    private String status;

    @JsonProperty("details")
    private String details;

    @JsonProperty("duration_ms")
    private Long durationMs;

    @JsonProperty("created_at")
    private String createdAt;

    public OperationLog() {
    }

    public OperationLog(String operationType, String status, Long durationMs) {
        this.operationType = operationType;
        this.status = status;
        this.durationMs = durationMs;
    }

    public OperationLog(String operationType, String status, String details, Long durationMs) {
        this.operationType = operationType;
        this.status = status;
        this.details = details;
        this.durationMs = durationMs;
    }

    public Long getId() {
        return id;
    }

    public void setId(Long id) {
        this.id = id;
    }

    public String getOperationType() {
        return operationType;
    }

    public void setOperationType(String operationType) {
        this.operationType = operationType;
    }

    public String getStatus() {
        return status;
    }

    public void setStatus(String status) {
        this.status = status;
    }

    public String getDetails() {
        return details;
    }

    public void setDetails(String details) {
        this.details = details;
    }

    public Long getDurationMs() {
        return durationMs;
    }

    public void setDurationMs(Long durationMs) {
        this.durationMs = durationMs;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }
}
