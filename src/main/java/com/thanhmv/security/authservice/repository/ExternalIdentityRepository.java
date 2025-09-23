package com.thanhmv.security.authservice.repository;

import com.thanhmv.security.authservice.model.entity.ExternalIdentity;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.Optional;

public interface ExternalIdentityRepository extends JpaRepository<ExternalIdentity, Long> {

    Optional<ExternalIdentity> findByProviderAndProviderUserId(String provider, String providerUserId);

    // đôi khi hữu ích khi cần tra cứu nhanh theo email (không bắt buộc)
    Optional<ExternalIdentity> findFirstByProviderAndEmail(String provider, String email);
}