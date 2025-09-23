package com.thanhmv.security.authservice.repository;

import com.thanhmv.security.authservice.model.entity.LoginAttempt;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

@Repository
public interface LoginAttemptRepository extends JpaRepository<LoginAttempt, String> {
}
