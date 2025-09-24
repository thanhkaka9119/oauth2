package com.thanhmv.security.authservice.repository;

import com.thanhmv.security.authservice.model.entity.UserEntity;
import org.springframework.data.jpa.repository.EntityGraph;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.util.Optional;

@Repository
public interface UserRepository extends JpaRepository<UserEntity, Long> {
    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<UserEntity> findByUsername(@Param("username") String username);

    @EntityGraph(attributePaths = {"roles", "roles.permissions"})
    Optional<UserEntity> findByEmail(@Param("email") String email);
}
