package com.thanhmv.security.authservice.controller;

import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class OAuth2LoginController {
    @GetMapping("/login-success")
    public String loginSuccess() {
        return "Login success! User: ";
    }

    @GetMapping("/login-failure")
    public String loginFailure() {
        return "Login failed!";
    }
}
