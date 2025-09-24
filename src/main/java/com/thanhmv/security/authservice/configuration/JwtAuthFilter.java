package com.thanhmv.security.authservice.configuration;

import com.thanhmv.security.authservice.common.util.JwtUtil;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@RequiredArgsConstructor
public class JwtAuthFilter extends OncePerRequestFilter {

    private final JwtUtil jwtUtil;

    @Override
    protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain filterChain) throws ServletException, IOException {
        String h = req.getHeader("Authorization");
        if (h != null && h.startsWith("Bearer ")) {
            String token = h.substring(7);
            if (jwtUtil.isTokenValid(token)) { /* invalid token -> no auth */
                Claims claims = jwtUtil.parse(token).getBody(); //parse lần 2 rất nhanh (đã cache parser)
                String email = claims.getSubject();
                @SuppressWarnings("unchecked")
                List<String> auths = (List<String>) claims.get("authorities");
                var authorities = auths == null ? List.<SimpleGrantedAuthority>of()
                        : auths.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

                var auth = new UsernamePasswordAuthenticationToken(email, null, authorities);
                SecurityContextHolder.getContext().setAuthentication(auth);
            }
        }
        filterChain.doFilter(req, res);
    }
}
