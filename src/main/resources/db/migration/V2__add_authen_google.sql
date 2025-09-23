DROP TABLE IF EXISTS external_identities;
-- Danh tính ngoài (Google, v.v.)
CREATE TABLE IF NOT EXISTS external_identities (
  id BIGINT AUTO_INCREMENT PRIMARY KEY,
  user_id BIGINT NOT NULL,
  provider VARCHAR(50) NOT NULL,          -- 'google', 'github'...
  provider_user_id VARCHAR(255) NOT NULL, -- OIDC 'sub'
  email VARCHAR(255),
  name VARCHAR(255),
  avatar_url VARCHAR(512),
  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  last_login_at TIMESTAMP NULL,
  CONSTRAINT uq_provider_subject UNIQUE (provider, provider_user_id),
  INDEX idx_ext_id_email (email),
  CONSTRAINT fk_ext_id_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);

ALTER TABLE users
  ADD COLUMN password_set BOOLEAN NOT NULL DEFAULT TRUE,
  ADD COLUMN email_verified BOOLEAN NOT NULL DEFAULT FALSE;

-- Bổ sung cột user_id và metadata
ALTER TABLE refresh_tokens
  ADD COLUMN user_id BIGINT NULL,
  ADD COLUMN created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  ADD COLUMN revoked BOOLEAN NOT NULL DEFAULT FALSE;

-- Backfill user_id từ username (nếu bạn đang dùng username đúng với users.username)
UPDATE refresh_tokens rt
JOIN users u ON u.username = rt.username
SET rt.user_id = u.id
WHERE rt.user_id IS NULL;

-- Thêm ràng buộc
ALTER TABLE refresh_tokens
  ADD CONSTRAINT fk_refresh_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

-- (Tuỳ chọn) bỏ cột username nếu đã xác nhận toàn bộ backfill OK
 ALTER TABLE refresh_tokens DROP COLUMN username;
