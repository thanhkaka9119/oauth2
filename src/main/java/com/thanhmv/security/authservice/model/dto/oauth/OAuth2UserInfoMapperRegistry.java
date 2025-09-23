package com.thanhmv.security.authservice.model.dto.oauth;

import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Map;

@Component
@RequiredArgsConstructor
public class OAuth2UserInfoMapperRegistry {

    // key = bean name (google, github, ...)
    private final Map<String, OAuth2UserInfoMapper> mappers;
    private final DefaultUserInfoMapper defaultMapper;

    public OAuth2UserInfoMapper get(String registrationId) {
        if (registrationId == null) return defaultMapper;
        OAuth2UserInfoMapper mapper = mappers.get(registrationId.toLowerCase());
        return mapper != null ? mapper : defaultMapper;
    }
}