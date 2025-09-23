package com.thanhmv.security.authservice.common.exception;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.thanhmv.security.authservice.common.util.ErrorCode;

import java.time.OffsetDateTime;
import java.util.Date;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record ErrorResponse(
        String code,
        int status,
        String error,
        String message,
        String path,
        Date timestamp
) {
    public static ErrorResponse of(
            ErrorCode ec, int status, String error, String message, String path
    ){
        return new ErrorResponse(
                ec.getCode(), status, error, message, path, new Date()
        );
    }
}
