package com.thanhmv.security.authservice.model.entity;

import jakarta.persistence.*;
import lombok.Getter; import lombok.Setter;
import java.util.Set;

@Getter
@Setter
@Entity
@Table(name = "roles")
public class RoleEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(nullable=false, unique=true, length=50)
    private String name; // ví dụ: ROLE_ADMIN

    private String description;

    @ManyToMany(fetch = FetchType.LAZY)
    @JoinTable(
            name = "role_permissions",
            joinColumns = @JoinColumn(name="role_id"),
            inverseJoinColumns = @JoinColumn(name="permission_id")
    )
    private Set<PermissionEntity> permissions;
}
