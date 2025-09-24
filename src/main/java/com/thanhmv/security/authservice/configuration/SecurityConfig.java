package com.thanhmv.security.authservice.configuration;

import com.thanhmv.security.authservice.common.exception.JsonAccessDeniedHandler;
import com.thanhmv.security.authservice.common.exception.JsonAuthEntryPoint;
import lombok.RequiredArgsConstructor;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.config.annotation.authentication.configuration.AuthenticationConfiguration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.web.SecurityFilterChain;

@Configuration
@EnableWebSecurity
@EnableMethodSecurity // dùng @PreAuthorize
@RequiredArgsConstructor
public class SecurityConfig {

    private final OAuth2LoginSuccessHandler oAuth2LoginSuccessHandler;
    private final JwtAuthFilter jwtAuthFilter;

    @Bean
    public SecurityFilterChain filterChain(HttpSecurity http) throws Exception {
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
                        .successHandler(oAuth2LoginSuccessHandler)
                        .failureUrl("/login-failure")
                )
                .addFilterBefore(jwtAuthFilter, org.springframework.security.web.authentication.UsernamePasswordAuthenticationFilter.class)
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

}
