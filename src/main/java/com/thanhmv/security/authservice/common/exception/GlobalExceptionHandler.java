package com.thanhmv.security.authservice.common.exception;

import com.thanhmv.security.authservice.common.util.ErrorCode;
import io.jsonwebtoken.ExpiredJwtException;
import io.jsonwebtoken.JwtException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.DisabledException;
import org.springframework.web.HttpMediaTypeNotSupportedException;
import org.springframework.web.HttpRequestMethodNotSupportedException;
import org.springframework.web.bind.MethodArgumentNotValidException;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.security.access.AccessDeniedException;

import java.util.stream.Collectors;

@RestControllerAdvice
public class GlobalExceptionHandler {
    private ResponseEntity<ErrorResponse> build(HttpStatus status, ErrorCode ec, String msg, String path){
        String reason = status.getReasonPhrase();
        return ResponseEntity.status(status)
                .body(ErrorResponse.of(ec, status.value(), reason, msg, path));
    }

    // 400 - Validation (body/form @Valid)
    @ExceptionHandler(MethodArgumentNotValidException.class)
    public ResponseEntity<ErrorResponse> handleInvalid(MethodArgumentNotValidException ex, HttpServletRequest req){
        String msg = ex.getBindingResult().getFieldErrors().stream()
                .map(f -> f.getField()+": "+f.getDefaultMessage())
                .collect(Collectors.joining("; "));
        return build(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, msg, req.getRequestURI());
    }

    // 400 - Validation (query/path)
    @ExceptionHandler(ConstraintViolationException.class)
    public ResponseEntity<ErrorResponse> handleConstraint(ConstraintViolationException ex, HttpServletRequest req){
        return build(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, ex.getMessage(), req.getRequestURI());
    }

    // 401 - Sai user/pass
    @ExceptionHandler(BadCredentialsException.class)
    public ResponseEntity<ErrorResponse> handleBadCred(BadCredentialsException ex, HttpServletRequest req){
        return build(HttpStatus.UNAUTHORIZED, ErrorCode.AUTH_BAD_CREDENTIALS, "Invalid credentials", req.getRequestURI());
    }

    // 423 - Tài khoản bị khóa tạm thời
    @ExceptionHandler(LockedAccountException.class)
    public ResponseEntity<ErrorResponse> handleLocked(LockedAccountException ex, HttpServletRequest req){
        return build(HttpStatus.LOCKED, ErrorCode.AUTH_ACCOUNT_LOCKED, ex.getMessage(), req.getRequestURI());
    }

    // 403 - Bị disable
    @ExceptionHandler(DisabledException.class)
    public ResponseEntity<ErrorResponse> handleDisabled(DisabledException ex, HttpServletRequest req){
        return build(HttpStatus.FORBIDDEN, ErrorCode.AUTH_ACCOUNT_DISABLED, "Account disabled", req.getRequestURI());
    }

    // 401 - JWT lỗi / hết hạn
    @ExceptionHandler(ExpiredJwtException.class)
    public ResponseEntity<ErrorResponse> handleJwtExpired(ExpiredJwtException ex, HttpServletRequest req){
        return build(HttpStatus.UNAUTHORIZED, ErrorCode.TOKEN_EXPIRED, "Access token expired", req.getRequestURI());
    }
    @ExceptionHandler(JwtException.class)
    public ResponseEntity<ErrorResponse> handleJwt(JwtException ex, HttpServletRequest req){
        return build(HttpStatus.UNAUTHORIZED, ErrorCode.TOKEN_INVALID, "Invalid token", req.getRequestURI());
    }

    // 403 - Không đủ quyền
    @ExceptionHandler(AccessDeniedException.class)
    public ResponseEntity<ErrorResponse> handleDenied(AccessDeniedException ex, HttpServletRequest req){
        return build(HttpStatus.FORBIDDEN, ErrorCode.AUTH_FORBIDDEN, "Access denied", req.getRequestURI());
    }

    // 405/415
    @ExceptionHandler(HttpRequestMethodNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMethod(HttpRequestMethodNotSupportedException ex, HttpServletRequest req){
        return build(HttpStatus.METHOD_NOT_ALLOWED, ErrorCode.METHOD_NOT_ALLOWED, ex.getMessage(), req.getRequestURI());
    }
    @ExceptionHandler(HttpMediaTypeNotSupportedException.class)
    public ResponseEntity<ErrorResponse> handleMedia(HttpMediaTypeNotSupportedException ex, HttpServletRequest req){
        return build(HttpStatus.UNSUPPORTED_MEDIA_TYPE, ErrorCode.UNSUPPORTED_MEDIA, ex.getMessage(), req.getRequestURI());
    }

    // 400 - IllegalArgument (như grant_type không hợp lệ)
    @ExceptionHandler(IllegalArgumentException.class)
    public ResponseEntity<ErrorResponse> handleIllegal(IllegalArgumentException ex, HttpServletRequest req){
        return build(HttpStatus.BAD_REQUEST, ErrorCode.VALIDATION_ERROR, ex.getMessage(), req.getRequestURI());
    }

    // 500 - fallback
    @ExceptionHandler(Exception.class)
    public ResponseEntity<ErrorResponse> handleOther(Exception ex, HttpServletRequest req){
        return build(HttpStatus.INTERNAL_SERVER_ERROR, ErrorCode.INTERNAL_ERROR, "Internal error", req.getRequestURI());
    }
}
