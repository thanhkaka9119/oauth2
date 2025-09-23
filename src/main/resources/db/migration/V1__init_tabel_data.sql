DROP TABLE IF EXISTS users, roles, user_roles, permissions, role_permissions, user_login_attempts, refresh_tokens;
CREATE TABLE users (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    full_name VARCHAR(100) NOT NULL,
    phone VARCHAR(20),
    email VARCHAR(100) UNIQUE,
    password VARCHAR(200) NOT NULL,
    address VARCHAR(255),
    enabled BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
);
CREATE TABLE roles (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,     -- ví dụ: ROLE_USER, ROLE_ADMIN
    description VARCHAR(255)
);

CREATE TABLE user_roles (
    user_id BIGINT NOT NULL,
    role_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, role_id),
    CONSTRAINT fk_user_roles_user FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    CONSTRAINT fk_user_roles_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE
);
CREATE TABLE permissions (
    id BIGINT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,    -- ví dụ: USER_READ, USER_UPDATE
    description VARCHAR(255)
);

CREATE TABLE role_permissions (
    role_id BIGINT NOT NULL,
    permission_id BIGINT NOT NULL,
    PRIMARY KEY (role_id, permission_id),
    CONSTRAINT fk_role_permissions_role FOREIGN KEY (role_id) REFERENCES roles(id) ON DELETE CASCADE,
    CONSTRAINT fk_role_permissions_perm FOREIGN KEY (permission_id) REFERENCES permissions(id) ON DELETE CASCADE
);
-- Insert roles
INSERT INTO roles (name, description) VALUES
('ROLE_USER', 'Người dùng cơ bản'),
('ROLE_ADMIN', 'Quản trị hệ thống');

-- Insert permissions
INSERT INTO permissions (name, description) VALUES
('USER_READ', 'Xem thông tin user'),
('USER_CREATE', 'Tạo user mới'),
('USER_UPDATE', 'Cập nhật thông tin user'),
('USER_DELETE', 'Xóa user');

-- Gán permission cho ROLE_USER (chỉ đọc)
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_USER' AND p.name = 'USER_READ';

-- Gán toàn bộ quyền cho ROLE_ADMIN
INSERT INTO role_permissions (role_id, permission_id)
SELECT r.id, p.id FROM roles r, permissions p
WHERE r.name = 'ROLE_ADMIN';

-- Insert default admin user
INSERT INTO users (username, full_name, phone, email, password, address, enabled)
VALUES (
    'admin',
    'System Administrator',
    '0909000000',
    'admin@example.com',
    '$2a$10$changemechangemechangemechangemechangemechangeme', -- bcrypt password placeholder
    'Head Office',
    TRUE
);

-- Gán ROLE_ADMIN cho admin
INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id FROM users u, roles r
WHERE u.username = 'admin' AND r.name = 'ROLE_ADMIN';

-- Bảng đếm số lần sai & thời điểm lock
CREATE TABLE IF NOT EXISTS user_login_attempts (
  username VARCHAR(50) PRIMARY KEY,
  failed_attempts INT NOT NULL DEFAULT 0,
  locked_until TIMESTAMP NULL
);

-- Lưu refresh token (random) + scope
CREATE TABLE IF NOT EXISTS refresh_tokens (
  token VARCHAR(128) PRIMARY KEY,
  username VARCHAR(50) NOT NULL,
  scope VARCHAR(255),
  expires_at TIMESTAMP NOT NULL
);