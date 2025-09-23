package com.thanhmv.security.authservice.model.dto.oauth;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;

public interface OAuth2UserInfoMapper {
    /** Trả về ID “registrationId” mà mapper này phục vụ: ví dụ "google", "github" */
    String registrationId();
    /** Map từ principal → DTO thống nhất */
    OAuth2UserInfo map(DefaultOAuth2User user);
}
