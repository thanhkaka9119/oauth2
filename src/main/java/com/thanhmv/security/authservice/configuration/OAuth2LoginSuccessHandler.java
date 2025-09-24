package com.thanhmv.security.authservice.configuration;

import com.thanhmv.security.authservice.model.dto.oauth.OAuth2UserInfo;
import com.thanhmv.security.authservice.model.dto.oauth.OAuth2UserInfoMapperRegistry;
import com.thanhmv.security.authservice.service.AuthService;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;

import java.io.IOException;

@Component
@RequiredArgsConstructor
public class OAuth2LoginSuccessHandler implements AuthenticationSuccessHandler {

    private final AuthService authService;
    private final OAuth2UserInfoMapperRegistry mapperRegistry;

    @Override
    public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response, Authentication authentication) throws IOException, ServletException {
        // Lấy thông tin từ Google
        DefaultOAuth2User oauthUser = (DefaultOAuth2User) authentication.getPrincipal();
        String registrationId = ((org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken) authentication)
                .getAuthorizedClientRegistrationId();

        OAuth2UserInfo info = mapperRegistry.get(registrationId).map(oauthUser);

        String redirectUrl = authService.linkOrCreate(info);

        response.sendRedirect(redirectUrl);
    }
}
