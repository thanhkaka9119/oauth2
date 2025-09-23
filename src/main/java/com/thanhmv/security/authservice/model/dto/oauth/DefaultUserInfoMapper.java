package com.thanhmv.security.authservice.model.dto.oauth;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component("defaultMapper")
public class DefaultUserInfoMapper implements OAuth2UserInfoMapper {

    @Override
    public String registrationId() { return "default"; }

    @Override
    public OAuth2UserInfo map(DefaultOAuth2User principal) {
        Map<String, Object> a = principal.getAttributes();
        String sub = firstNonNull(a.get("sub"), a.get("id"), a.get("user_id"));
        String email = firstNonNull(a.get("email"), nested(a, "email", "value"));
        String name = firstNonNull(a.get("name"), a.get("login"), a.get("preferred_username"));
        String pic  = firstNonNull(a.get("picture"), a.get("avatar_url"));
        return OAuth2UserInfo.builder()
                .sub(asStr(sub)).email(asStr(email)).name(asStr(name)).picture(asStr(pic))
                .provider("unknown")
                .build();
    }

    private static String asStr(Object v) { return v == null ? null : String.valueOf(v); }
    private static String firstNonNull(Object... vs) {
        for (Object v : vs) if (v != null && !String.valueOf(v).isBlank()) return String.valueOf(v);
        return null;
    }
    @SuppressWarnings("unchecked")
    private static String nested(Map<String, Object> a, String obj, String key) {
        Object o = a.get(obj);
        if (o instanceof Map<?,?> m) {
            Object v = ((Map<String,Object>) m).get(key);
            return v != null ? String.valueOf(v) : null;
        }
        return null;
    }
}
