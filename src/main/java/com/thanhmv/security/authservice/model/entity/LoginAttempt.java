package com.thanhmv.security.authservice.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "user_login_attempts")
public class LoginAttempt {
    @Id
    @Column(length = 50)
    private String username;

    @Column(name="failed_attempts", nullable=false)
    private int failedAttempts;

    @Column(name="locked_until")
    private Instant lockedUntil;
}