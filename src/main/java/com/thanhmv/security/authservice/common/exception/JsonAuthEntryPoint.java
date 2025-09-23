package com.thanhmv.security.authservice.common.exception;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.thanhmv.security.authservice.common.util.ErrorCode;
import jakarta.servlet.http.*;
import org.springframework.http.HttpStatus;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.AuthenticationEntryPoint;

import java.io.IOException;

public class JsonAuthEntryPoint implements AuthenticationEntryPoint {
    private final ObjectMapper om = new ObjectMapper();

    @Override
    public void commence(HttpServletRequest req, HttpServletResponse res, AuthenticationException ex) throws IOException {
        res.setStatus(HttpStatus.UNAUTHORIZED.value());
        res.setContentType("application/json");
        var body = ErrorResponse.of(
                ErrorCode.AUTH_UNAUTHORIZED,
                HttpStatus.UNAUTHORIZED.value(),
                HttpStatus.UNAUTHORIZED.getReasonPhrase(),
                "Unauthorized",
                req.getRequestURI()
        );
        om.writeValue(res.getOutputStream(), body);
    }
}
