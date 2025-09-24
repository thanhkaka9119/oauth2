package com.thanhmv.security.authservice.service;

import com.thanhmv.security.authservice.common.exception.AccountNotFoundException;
import com.thanhmv.security.authservice.common.exception.LockedAccountException;
import com.thanhmv.security.authservice.common.util.JwtUtil;
import com.thanhmv.security.authservice.model.dto.oauth.OAuth2UserInfo;
import com.thanhmv.security.authservice.model.entity.*;
import com.thanhmv.security.authservice.repository.*;
import jakarta.transaction.Transactional;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.security.crypto.password.PasswordEncoder;

import java.time.Instant;
import java.util.*;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class AuthService {
    private final UserRepository userRepo;
    private final LoginAttemptRepository attemptRepo;
    private final RefreshTokenRepository refreshRepo;
    private final PasswordEncoder passwordEncoder;
    private final RoleRepository roleRepository;
    private final ExternalIdentityRepository extIdRepo;
    private final UserRoleRepository userRoleRepo;
    private final JwtUtil jwtUtil;
    private final org.springframework.core.env.Environment env;

    public Map<String, Object> passwordGrant(String email, String password, String scope) {
        // 1) Kiểm tra lock
        LoginAttempt la = attemptRepo.findById(email).orElseGet(() -> {
            LoginAttempt x = new LoginAttempt();
            x.setEmail(email);
            x.setFailedAttempts(0);
            return x;
        });
        int maxFailed = Integer.parseInt(env.getProperty("auth.login.max-failed", "3"));
        int lockMinutes = Integer.parseInt(env.getProperty("auth.login.lock-minutes", "15"));

        if (la.getLockedUntil() != null && la.getLockedUntil().isAfter(Instant.now())) {
            throw new LockedAccountException("Account temporarily locked. Try again later.");
        }

        // 2) Tải user + quyền
        UserEntity user = userRepo.findByEmail(email)
                .orElseThrow(() -> new AccountNotFoundException("Invalid email information"));
        if (Boolean.FALSE.equals(user.getEnabled())) {
            throw new org.springframework.security.authentication.DisabledException("Account disabled");
        }

        // 3) So sánh mật khẩu
        if (!passwordEncoder.matches(password, user.getPassword())) {
            la.setFailedAttempts(la.getFailedAttempts() + 1);
            if (la.getFailedAttempts() >= maxFailed) {
                la.setLockedUntil(Instant.now().plusSeconds(lockMinutes * 60L));
                la.setFailedAttempts(0); // reset counter sau khi khóa
            }
            attemptRepo.save(la);
            throw new org.springframework.security.authentication.BadCredentialsException("Invalid password information");
        }

        // 4) Reset đếm khi login thành công
        la.setFailedAttempts(0);
        la.setLockedUntil(null);
        attemptRepo.save(la);

        // 5) Authorities = ROLE_x + permission
        List<String> authorities = buildAuthorities(user);

        // 6) Tạo access token & refresh token
        long accessSecs = Long.parseLong(env.getProperty("security.jwt.access-token-seconds", "36000"));
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), authorities, accessSecs);

        String refreshToken = UUID.randomUUID().toString().replace("-", "");
        Instant rtExp = Instant.now()
                .plusSeconds(Long.parseLong(env.getProperty("security.jwt.refresh-token-seconds", "2592000")));
        RefreshToken rt = new RefreshToken();
        rt.setToken(refreshToken);
        rt.setUserId(user.getId());
        rt.setScope(scope);
        rt.setCreatedAt(Instant.now());
        rt.setExpiresAt(rtExp);
        rt.setRevoked(false);
        refreshRepo.save(rt);

        // 7) Trả đúng format (expires_in = 35999 như yêu cầu)
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", accessToken);
        resp.put("token_type", "bearer");
        resp.put("refresh_token", refreshToken);
        resp.put("scope", scope);
        resp.put("expires_in", 35999);
        return resp;
    }

    public Map<String, Object> refreshGrant(String refreshToken) {
        RefreshToken rt = refreshRepo.findByToken(refreshToken)
                .orElseThrow(() -> new IllegalArgumentException("Invalid refresh_token"));
        if (rt.getExpiresAt().isBefore(Instant.now())) {
            refreshRepo.delete(rt);
            throw new io.jsonwebtoken.ExpiredJwtException(null, null, "Refresh token expired");
        }
        UserEntity user = userRepo.findById(rt.getUserId())
                .orElseThrow(() -> new RuntimeException("User not found"));
        List<String> authorities = buildAuthorities(user);

        long accessSecs = Long.parseLong(env.getProperty("security.jwt.access-token-seconds", "36000"));
        String accessToken = jwtUtil.generateAccessToken(user.getEmail(), authorities, accessSecs);

        // (tuỳ bạn: có thể rotate refresh token, ở đây giữ nguyên)
        Map<String, Object> resp = new LinkedHashMap<>();
        resp.put("access_token", accessToken);
        resp.put("token_type", "bearer");
        resp.put("refresh_token", rt.getToken());
        resp.put("scope", rt.getScope());
        return resp;
    }

    public List<String> buildAuthorities(UserEntity user) {
        Set<String> auths = new HashSet<>();
        if (user.getRoles() != null) {
            for (RoleEntity r : user.getRoles()) {
                if (r.getName() != null) auths.add(r.getName()); // ROLE_*
                if (r.getPermissions() != null) {
                    auths.addAll(
                            r.getPermissions().stream()
                                    .map(PermissionEntity::getName) // USER_READ, ...
                                    .filter(Objects::nonNull)
                                    .collect(Collectors.toSet())
                    );
                }
            }
        }
        return new ArrayList<>(auths);
    }

    @Transactional
    public String linkOrCreate(OAuth2UserInfo info) {

        // info.sub (provider_user_id), info.email, info.name, info.picture

        // 1) Tìm theo provider+subject
        UserEntity user = null;
        var ei = extIdRepo.findByProviderAndProviderUserId("google", info.getSub());
        if (ei.isPresent()) {
            ei.get().setLastLoginAt(Instant.now());
            extIdRepo.save(ei.get());
            user = ei.get().getUser();
        }

        // 2) Nếu chưa có, thử map bằng email
        if (user == null) {
            user = userRepo.findByEmail(info.getEmail()).orElse(null);
            if (user == null){
                // 2a) Tạo user mới
                String randomBcrypt = passwordEncoder.encode(UUID.randomUUID().toString());

                user = new UserEntity();
                user.setFullName(info.getName());
                user.setEmail(info.getEmail());
                user.setPassword(randomBcrypt);
                user.setEnabled(true);
                userRepo.save(user);

                // Gán ROLE_USER mặc định
                RoleEntity roleUser = roleRepository.findByName("ROLE_USER").orElseThrow();
                if (!userRoleRepo.existsByUser_IdAndRole_Id(user.getId(), roleUser.getId())) {
                    userRoleRepo.save(UserRoleEntity.of(user, roleUser));
                }
            }
        }

        // 3) Tạo liên kết external identity
        ExternalIdentity link = new ExternalIdentity();
        link.setUser(user);
        link.setProvider("google");
        link.setProviderUserId(info.getSub());
        link.setEmail(info.getEmail());
        link.setName(info.getName());
        link.setAvatarUrl(info.getPicture());
        link.setLastLoginAt(Instant.now());
        extIdRepo.save(link);

        // Lấy authorities từ DB rồi phát JWT
        long accessSecs = Long.parseLong(env.getProperty("security.jwt.access-token-seconds", "36000"));
        List<String> authorities = buildAuthorities(user);
        String jwt = jwtUtil.generateAccessToken(user.getEmail(), authorities, accessSecs);

        // Trả JWT cho client
        String target = env.getProperty("app.frontend.success-url",
                "http://localhost:3000/auth/callback");

        // Đưa token vào fragment để tránh xuất hiện ở Referer/log server
        String redirectUrl = target + "#access_token=" +
                java.net.URLEncoder.encode(jwt, java.nio.charset.StandardCharsets.UTF_8);

        return redirectUrl;
    }


}
