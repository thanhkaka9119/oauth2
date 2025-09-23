package com.thanhmv.security.authservice.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "refresh_tokens")
public class RefreshToken {
    @Id
    @Column(length = 128)
    private String token;

    @Column(length=255)
    private String scope; // echo lại scope client gửi lên

    @Column(name="expires_at", nullable=false)
    private Instant expiresAt;

    @Column(name="user_id")
    private Long userId;

    @Column(name="created_at")
    private Instant createdAt;

    @Column(name="revoked")
    private Boolean revoked;

}
