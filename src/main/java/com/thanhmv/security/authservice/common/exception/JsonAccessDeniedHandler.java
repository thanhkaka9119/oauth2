package com.thanhmv.security.authservice.common.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thanhmv.security.authservice.common.util.ErrorCode;
import jakarta.servlet.http.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.access.AccessDeniedHandler;

import java.io.IOException;

public class JsonAccessDeniedHandler implements AccessDeniedHandler {
    private final ObjectMapper om = new ObjectMapper();

    @Override
    public void handle(HttpServletRequest req, HttpServletResponse res, AccessDeniedException ex) throws IOException {
        res.setStatus(HttpStatus.FORBIDDEN.value());
        res.setContentType("application/json");
        var body = ErrorResponse.of(
                ErrorCode.AUTH_FORBIDDEN,
                HttpStatus.FORBIDDEN.value(),
                HttpStatus.FORBIDDEN.getReasonPhrase(),
                "Access denied",
                req.getRequestURI()
        );
        om.writeValue(res.getOutputStream(), body);
    }
}
