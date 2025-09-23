package com.thanhmv.security.authservice.common.util;
import io.jsonwebtoken.*;
import io.jsonwebtoken.security.Keys;
import org.springframework.stereotype.Component;

import java.security.Key;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;

@Component
public class JwtUtil {
    private final Key key;
    private final String issuer;

    public JwtUtil(org.springframework.core.env.Environment env) {
        String secret = env.getProperty("security.jwt.secret");
        this.key = Keys.hmacShaKeyFor(secret.getBytes());
        this.issuer = env.getProperty("security.jwt.issuer", "jwt-auth-service");
    }

    public String generateAccessToken(String username, List<String> authorities,
                                      long expiresInSeconds) {
        Instant now = Instant.now();
        return Jwts.builder()
                .setSubject(username) //là claim chuẩn trong JWT để định danh "chủ thể" token.
                .setIssuer(issuer)//ai phát hành token (tên hệ thống, service).
                .setIssuedAt(Date.from(now))//thời điểm phát hành token.
                .setExpiration(Date.from(now.plusSeconds(expiresInSeconds)))//thời điểm token hết hạn. ví dụ 3600 = 1h.
                .addClaims(Map.of("authorities", authorities))
                .signWith(key, SignatureAlgorithm.HS256)//thuật toán mã hóa
                .compact();
    }

    public Jws<Claims> parse(String token) {
        return Jwts.parserBuilder()
                .setSigningKey(key)
                .build()
                .parseClaimsJws(token);
    }
}
