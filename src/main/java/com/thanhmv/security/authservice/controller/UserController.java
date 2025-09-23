package com.thanhmv.security.authservice.controller;

import org.springframework.security.access.prepost.PreAuthorize;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/users")
public class UserController {
    @GetMapping("/me")
    public String me(org.springframework.security.core.Authentication auth) {
        return "Hello " + auth.getName();
    }

    @PreAuthorize("hasAuthority('ROLE_ADMIN')")
    @GetMapping("/admin-area")
    public String adminOnly() {
        return "Admin content";
    }

    @PreAuthorize("hasAuthority('USER_READ')")
    @GetMapping("/read")
    public String canRead() {
        return "You have USER_READ permission";
    }
}
