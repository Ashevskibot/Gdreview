-- ============================================================
-- GDREVIEW — актуальная схема БД (PostgreSQL)
-- Изменения в этой версии:
--   1. reviews.user_id -> users.id теперь ON DELETE CASCADE
--      (при удалении пользователя все его отзывы удаляются
--      автоматически, ошибка foreign key constraint больше не возникает)
--   2. users.register_ip — IP-адрес, с которого была выполнена регистрация
-- ============================================================

CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(100) UNIQUE NOT NULL,
    email VARCHAR(255) UNIQUE NOT NULL,
    password_hash VARCHAR(255),         -- NULL для аккаунтов, созданных через Google Sign-In
    google_id VARCHAR(255),             -- Google OAuth subject (sub); уникальный индекс ниже
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    avatar TEXT,
    banner TEXT,
    frame VARCHAR(50) DEFAULT 'frame-default',
    description VARCHAR(150),
    socials TEXT,
    is_verified BOOLEAN DEFAULT FALSE,
    verify_code VARCHAR(10),
    reset_code VARCHAR(10),
    reset_expires BIGINT,
    register_ip VARCHAR(45)          -- поддерживает как IPv4, так и IPv6
);

CREATE TABLE IF NOT EXISTS reviews (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    level_id VARCHAR(50) NOT NULL,
    level_name VARCHAR(255),
    level_author VARCHAR(255),
    difficulty VARCHAR(50),
    difficulty_face VARCHAR(100),
    stars INTEGER,
    -- Актуальная 5-осевая система оценок:
    gameplay INTEGER,          -- Gameplay (обычные уровни) / Direction & Camera (Auto)
    sync_rhythm INTEGER,       -- Synchronization / Rhythm
    design_deco INTEGER,       -- Design / Decoration
    creativity INTEGER,        -- Idea / Creativity
    optimization INTEGER,      -- Optimization (LDM, performance)
    -- Устаревшие колонки старой 6-осевой системы (сохранены для истории):
    flow INTEGER,
    decoration INTEGER,
    music INTEGER,
    originality INTEGER,
    final_score NUMERIC(4,2),
    -- title и review_text равны NULL для rating-only записей (пользователь
    -- опубликовал только оценки без текстовой рецензии).
    title VARCHAR(30),
    review_text TEXT,
    saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS review_likes (
    id SERIAL PRIMARY KEY,
    review_id INTEGER REFERENCES reviews(id) ON DELETE CASCADE,
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(review_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_reviews_level ON reviews(level_id);
CREATE INDEX IF NOT EXISTS idx_reviews_saved ON reviews(saved_at DESC);
CREATE INDEX IF NOT EXISTS idx_likes_review ON review_likes(review_id);

-- ============================================================
-- МИГРАЦИЯ для уже существующей БД (если таблицы уже созданы
-- без ON DELETE CASCADE). server.js применяет её автоматически
-- при старте, но её можно выполнить и вручную:
-- ============================================================

ALTER TABLE reviews DROP CONSTRAINT IF EXISTS reviews_user_id_fkey;
ALTER TABLE reviews
    ADD CONSTRAINT reviews_user_id_fkey
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE;

ALTER TABLE users ADD COLUMN IF NOT EXISTS register_ip VARCHAR(45);
UPDATE users SET description = LEFT(description, 150) WHERE CHAR_LENGTH(description) > 150;
ALTER TABLE users ALTER COLUMN description TYPE VARCHAR(150);
UPDATE reviews SET title = LEFT(title, 30) WHERE CHAR_LENGTH(title) > 30;
ALTER TABLE reviews ALTER COLUMN title TYPE VARCHAR(30);

-- Миграция на 5-осевую систему оценок (server.js применяет автоматически):
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS sync_rhythm INTEGER;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS design_deco INTEGER;
ALTER TABLE reviews ADD COLUMN IF NOT EXISTS creativity INTEGER;
UPDATE reviews SET
    sync_rhythm = COALESCE(sync_rhythm, music),
    design_deco = COALESCE(design_deco, decoration),
    creativity  = COALESCE(creativity, originality)
WHERE sync_rhythm IS NULL OR design_deco IS NULL OR creativity IS NULL;

-- ============================================================
-- Прохождения (walkthroughs) и права администратора
-- ============================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS is_admin BOOLEAN DEFAULT FALSE;

CREATE TABLE IF NOT EXISTS walkthroughs (
    id SERIAL PRIMARY KEY,
    level_id VARCHAR(50) NOT NULL,
    level_name VARCHAR(255),
    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
    youtube_url TEXT NOT NULL,
    video_id VARCHAR(20) NOT NULL,
    status VARCHAR(20) DEFAULT 'pending',   -- pending | approved | rejected
    submitted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    reviewed_at TIMESTAMP,
    reviewed_by INTEGER REFERENCES users(id) ON DELETE SET NULL
);

CREATE INDEX IF NOT EXISTS idx_walkthroughs_level ON walkthroughs(level_id, status);
CREATE INDEX IF NOT EXISTS idx_walkthroughs_status ON walkthroughs(status, submitted_at DESC);

-- ============================================================
-- Google Sign-In (server.js применяет автоматически при старте)
-- ============================================================

ALTER TABLE users ADD COLUMN IF NOT EXISTS google_id VARCHAR(255);
ALTER TABLE users ALTER COLUMN password_hash DROP NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS idx_users_google_id ON users(google_id);
