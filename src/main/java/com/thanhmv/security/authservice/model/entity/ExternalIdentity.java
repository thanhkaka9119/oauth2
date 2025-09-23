package com.thanhmv.security.authservice.model.entity;

import jakarta.persistence.Entity;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;
import jakarta.persistence.*;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.UpdateTimestamp;

import java.time.Instant;

@Getter
@Setter
@Entity
@Table(name = "external_identities")
public class ExternalIdentity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    // FK -> users.id
    @ManyToOne(fetch = FetchType.LAZY, optional = false)
    @JoinColumn(
            name = "user_id",
            nullable = false,
            foreignKey = @ForeignKey(name = "fk_ext_id_user")
    )
    private UserEntity user;

    // Ví dụ: "google", "github"...
    @Column(name = "provider", nullable = false, length = 50)
    private String provider;

    // OIDC 'sub'
    @Column(name = "provider_user_id", nullable = false, length = 255)
    private String providerUserId;

    @Column(name = "email", length = 255)
    private String email;

    @Column(name = "name", length = 255)
    private String name;

    @Column(name = "avatar_url", length = 512)
    private String avatarUrl;

    @CreationTimestamp
    @Column(name = "created_at", updatable = false)
    private Instant createdAt;

    @UpdateTimestamp
    @Column(name = "updated_at")
    private Instant updatedAt;

    @Column(name = "last_login_at")
    private Instant lastLoginAt;

    // equals/hashCode theo id để tránh bug với @ManyToOne (Hibernate best practice)
    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof ExternalIdentity that)) return false;
        return id != null && id.equals(that.id);
    }

    @Override
    public int hashCode() { return 31; }

    @Override
    public String toString() {
        return "ExternalIdentity{id=%d, provider='%s', providerUserId='%s'}"
                .formatted(id, provider, providerUserId);
    }
}
