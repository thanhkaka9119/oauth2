package com.thanhmv.security.authservice.model.dto.oauth;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class OAuth2UserInfo {
    private String sub;
    private String email;
    private String name;
    private String picture;
    private String provider;
}
