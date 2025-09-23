package com.thanhmv.security.authservice.model.dto.oauth;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component("google") // bean name = registrationId
public class GoogleUserInfoMapper implements OAuth2UserInfoMapper {

    @Override
    public String registrationId() { return "google"; }

    @Override
    public OAuth2UserInfo map(DefaultOAuth2User principal) {
        Map<String, Object> a = principal.getAttributes();
        return OAuth2UserInfo.builder()
                .sub(asStr(a.get("sub")))
                .email(asStr(a.get("email")))
                .name(asStr(a.get("name")))
                .picture(asStr(a.get("picture")))
                .provider("google")
                .build();
    }

    private static String asStr(Object v) { return v == null ? null : String.valueOf(v); }
}
