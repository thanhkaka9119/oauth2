package com.thanhmv.security.authservice.model.entity;

import jakarta.persistence.*;
import lombok.Getter;
import lombok.Setter;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "users")
public class UserEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false, unique=true, length=50)
    private String username;

    @Column(nullable=false, length=200)
    private String password;

    @Column(name="full_name", nullable=false, length=100)
    private String fullName;

    private String phone;
    private String email;
    private String address;

    private Boolean enabled = true;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "user_roles",
            joinColumns = @JoinColumn(name="user_id"),
            inverseJoinColumns = @JoinColumn(name="role_id")
    )
    private Set<RoleEntity> roles;

    @Column(name="password_set", nullable=false)
    private Boolean passwordSet = true;
    @Column(name="email_verified", nullable=false)
    private Boolean emailVerified = true;
}