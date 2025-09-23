package com.thanhmv.security.authservice.repository;

import com.thanhmv.security.authservice.model.entity.UserRoleEntity;
import com.thanhmv.security.authservice.model.entity.UserRoleId;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface UserRoleRepository extends JpaRepository<UserRoleEntity, UserRoleId> {
    boolean existsByUser_IdAndRole_Id(Long userId, Long roleId);
}