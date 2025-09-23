package com.thanhmv.security.authservice.common.util;

public enum ErrorCode {
    AUTH_UNAUTHORIZED("AUTH-401"),
    AUTH_FORBIDDEN("AUTH-403"),
    AUTH_BAD_CREDENTIALS("AUTH-001"),
    AUTH_ACCOUNT_LOCKED("AUTH-002"),
    AUTH_ACCOUNT_DISABLED("AUTH-003"),
    TOKEN_INVALID("AUTH-101"),
    TOKEN_EXPIRED("AUTH-102"),
    REFRESH_INVALID("AUTH-103"),
    VALIDATION_ERROR("REQ-001"),
    METHOD_NOT_ALLOWED("REQ-002"),
    UNSUPPORTED_MEDIA("REQ-003"),
    NOT_FOUND("REQ-004"),
    INTERNAL_ERROR("SYS-001");

    private final String code;
    ErrorCode(String code){ this.code = code; }
    public String getCode(){ return code; }
}
