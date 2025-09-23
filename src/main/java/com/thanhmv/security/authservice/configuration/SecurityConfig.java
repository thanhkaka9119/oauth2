package com.thanhmv.security.authservice.configuration;

import com.thanhmv.security.authservice.common.exception.JsonAccessDeniedHandler;
import com.thanhmv.security.authservice.common.exception.JsonAuthEntryPoint;
import com.thanhmv.security.authservice.common.util.JwtUtil;
import com.thanhmv.security.authservice.model.dto.oauth.OAuth2UserInfo;
import com.thanhmv.security.authservice.model.dto.oauth.OAuth2UserInfoMapperRegistry;
import com.thanhmv.security.authservice.service.AuthService;
import io.jsonwebtoken.Claims;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.crypto.password.PasswordEncoder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;
import java.util.stream.Collectors;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // dùng @PreAuthorize
@RequiredArgsConstructor
public class SecurityConfig {

    private final JwtUtil jwtUtil;
    private final org.springframework.core.env.Environment env;
    private final OAuth2UserInfoMapperRegistry mapperRegistry;
    private final AuthService authService;

    @Bean
    public PasswordEncoder passwordEncoder() {
        return new BCryptPasswordEncoder();
    }

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http, JwtAuthFilter jwtFilter) throws Exception {
        http
                .cors(cors -> cors.configurationSource(request -> {
                    var c = new org.springframework.web.cors.CorsConfiguration();
                    c.setAllowedOrigins(java.util.List.of("http://localhost:3000")); // FE dev
                    c.setAllowedMethods(java.util.List.of("GET","POST","PUT","DELETE","PATCH","OPTIONS"));
                    c.setAllowedHeaders(java.util.List.of("*"));
                    c.setExposedHeaders(java.util.List.of("Authorization")); // nếu muốn FE đọc header này
                    c.setAllowCredentials(false); // vì bạn đang dùng token trên header, không dùng cookie
                    c.setMaxAge(3600L);
                    return c;
                }))
                .csrf(csrf -> csrf.disable())
                .sessionManagement(sm -> sm.sessionCreationPolicy(
                        org.springframework.security.config.http.SessionCreationPolicy.STATELESS))
                .authorizeHttpRequests(auth -> auth
                        .requestMatchers( "/login-failure", "/oauth/login", "/oauth/genPassword", "/health").permitAll()
                        .anyRequest().authenticated()
                )
                // Đăng nhập OAuth2 (Google, GitHub…)
                .oauth2Login(oauth2 -> oauth2
                        .successHandler((request, response, authentication) -> {
                            // Lấy thông tin từ Google
                            DefaultOAuth2User oauthUser = (DefaultOAuth2User) authentication.getPrincipal();
                            String registrationId = ((org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken) authentication)
                                    .getAuthorizedClientRegistrationId();

                            // Lấy mapper theo registrationId
                            OAuth2UserInfo info = mapperRegistry.get(registrationId).map(oauthUser);

                            // Link / tạo user nội bộ
                            var user = authService.linkOrCreate(info);

                            // Lấy authorities từ DB rồi phát JWT
                            long accessSecs = Long.parseLong(env.getProperty("security.jwt.access-token-seconds", "36000"));
                            List<String> authorities = authService.buildAuthorities(user);
                            String jwt = jwtUtil.generateAccessToken(user.getUsername(), authorities, accessSecs);

                            // Trả JWT cho client
                            String target = env.getProperty("app.frontend.success-url",
                                    "http://localhost:3000/auth/callback");

                            // Đưa token vào fragment để tránh xuất hiện ở Referer/log server
                            String redirectUrl = target + "#access_token=" +
                                    java.net.URLEncoder.encode(jwt, java.nio.charset.StandardCharsets.UTF_8);

                            response.sendRedirect(redirectUrl);
                        })
                        .failureUrl("/login-failure")
                )
                .addFilterBefore(jwtFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
                .exceptionHandling(eh -> eh
                        .authenticationEntryPoint(new JsonAuthEntryPoint())
                        .accessDeniedHandler(new JsonAccessDeniedHandler())
                );
        return http.build();
    }

    @Bean
    public AuthenticationManager authenticationManager(AuthenticationConfiguration cfg) throws Exception {
        return cfg.getAuthenticationManager();
    }

    // Filter kiểm tra Bearer token
    @Bean
    public JwtAuthFilter jwtAuthFilter(JwtUtil jwtUtil) {
        return new JwtAuthFilter(jwtUtil);
    }

    public static class JwtAuthFilter extends OncePerRequestFilter {
        private final JwtUtil jwtUtil;
        public JwtAuthFilter(JwtUtil jwtUtil) { this.jwtUtil = jwtUtil; }

        @Override
        protected void doFilterInternal(HttpServletRequest req, HttpServletResponse res, FilterChain chain)
                throws IOException, jakarta.servlet.ServletException {
            String h = req.getHeader("Authorization");
            if (h != null && h.startsWith("Bearer ")) {
                String token = h.substring(7);
                try {
                    Claims claims = jwtUtil.parse(token).getBody();
                    String username = claims.getSubject();
                    @SuppressWarnings("unchecked")
                    List<String> auths = (List<String>) claims.get("authorities");
                    var authorities = auths == null ? List.<SimpleGrantedAuthority>of()
                            : auths.stream().map(SimpleGrantedAuthority::new).collect(Collectors.toList());

                    var auth = new UsernamePasswordAuthenticationToken(username, null, authorities);
                    SecurityContextHolder.getContext().setAuthentication(auth);
                } catch (Exception ignored) { /* invalid token -> no auth */ }
            }
            chain.doFilter(req, res);
        }
    }
}
