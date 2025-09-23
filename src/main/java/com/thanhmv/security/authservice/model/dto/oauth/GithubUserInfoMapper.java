package com.thanhmv.security.authservice.model.dto.oauth;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component("github") // bean name = registrationId
public class GithubUserInfoMapper implements OAuth2UserInfoMapper {

    @Override
    public String registrationId() { return "github"; }

    @Override
    public OAuth2UserInfo map(DefaultOAuth2User principal) {
        Map<String, Object> a = principal.getAttributes();
        // GitHub không có "sub"; dùng "id"
        return OAuth2UserInfo.builder()
                .sub(asStr(a.get("id")))
                .email(asStr(a.get("email")))          // có thể null nếu user ẩn email
                .name(asStr(a.get("name") != null ? a.get("name") : a.get("login")))
                .picture(asStr(a.get("avatar_url")))
                .provider("github")
                .build();
    }

    private static String asStr(Object v) { return v == null ? null : String.valueOf(v); }
}