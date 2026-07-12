const express = require('express');
const path = require('path');
const https = require('https');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const dns = require('dns');

// 🚀 КРИТИЧЕСКИ ВАЖНЫЙ ФИКС ДЛЯ RAILWAY: 
// Заставляем сервер общаться с Google только по IPv4. 
// Это обходит блокировку и решает проблему "Connection timeout"
dns.setDefaultResultOrder('ipv4first');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'fallback_secret_key'; 

// Используем альтернативный порт 587 (STARTTLS), который открыт на всех хостингах
const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587,
    secure: false, // Для порта 587 должно быть false
    requireTLS: true,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
});

const pool = new Pool({ connectionString: process.env.DATABASE_URL });

pool.connect().then(async (client) => {
    console.log('✅ Подключились к базе данных!');
    await client.query(`
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(100) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS reviews (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id),
            level_id VARCHAR(50) NOT NULL,
            level_name VARCHAR(255),
            level_author VARCHAR(255),
            difficulty VARCHAR(50),
            difficulty_face VARCHAR(100),
            stars INTEGER,
            gameplay INTEGER, flow INTEGER, decoration INTEGER, music INTEGER, originality INTEGER, optimization INTEGER,
            final_score NUMERIC(4,2), review_text TEXT, saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    `);
    
    await client.query(`
        ALTER TABLE users 
        ADD COLUMN IF NOT EXISTS avatar TEXT,
        ADD COLUMN IF NOT EXISTS banner TEXT,
        ADD COLUMN IF NOT EXISTS frame VARCHAR(50) DEFAULT 'frame-default',
        ADD COLUMN IF NOT EXISTS description TEXT,
        ADD COLUMN IF NOT EXISTS socials TEXT,
        ADD COLUMN IF NOT EXISTS is_verified BOOLEAN DEFAULT FALSE,
        ADD COLUMN IF NOT EXISTS verify_code VARCHAR(10),
        ADD COLUMN IF NOT EXISTS reset_code VARCHAR(10),
        ADD COLUMN IF NOT EXISTS reset_expires BIGINT;
    `).catch(() => {});

    client.release();
    console.log('✅ Таблицы готовы к работе!');
}).catch(err => console.error('❌ Ошибка базы данных:', err.stack));

app.use(express.json({ limit: '20mb' })); 
app.use(express.static(path.join(__dirname, 'public')));

const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Необходима авторизация' });
    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Сессия истекла' });
        req.user = user; next();
    });
};

const generateCode = () => Math.floor(100000 + Math.random() * 900000).toString();

// Функция отправки письма (работает в фоне)
function sendEmail(to, subject, text) {
    transporter.sendMail({ 
        from: `"GD Review" <${process.env.EMAIL_USER}>`, 
        to, 
        subject, 
        text 
    }).then(() => console.log(`📧 Письмо успешно отправлено на ${to}`))
      .catch(err => console.error(`❌ Ошибка отправки письма на ${to}:`, err.message));
}

async function uploadToCloud(base64Image) {
    if (!base64Image || !base64Image.startsWith('data:image')) return base64Image;
    const base64Data = base64Image.split(',')[1];
    const params = new URLSearchParams(); params.append('image', base64Data);
    try {
        const response = await fetch(`https://api.imgbb.com/1/upload?key=${process.env.IMGBB_API_KEY}`, { method: 'POST', body: params });
        const result = await response.json();
        if (result.success) return result.data.url;
    } catch (e) { console.error('Ошибка загрузки в облако:', e); }
    return base64Image;
}

// ==========================================
// 1. СИСТЕМА РЕГИСТРАЦИИ И ВХОДА
// ==========================================
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        
        if (userExists.rows.length > 0) {
            if (userExists.rows[0].is_verified) return res.status(400).json({ error: 'Пользователь уже существует' });
            await pool.query('DELETE FROM reviews WHERE user_id = $1', [userExists.rows[0].id]).catch(()=>{});
            await pool.query('DELETE FROM users WHERE id = $1', [userExists.rows[0].id]);
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);
        const code = generateCode();

        await pool.query(
            'INSERT INTO users (username, email, password_hash, verify_code) VALUES ($1, $2, $3, $4)',
            [username, email, passwordHash, code]
        );

        console.log(`\n=========================================`);
        console.log(`🔑 КОД РЕГИСТРАЦИИ ДЛЯ ${email}: [ ${code} ]`);
        console.log(`=========================================\n`);

        sendEmail(email, 'Код подтверждения GD Review', `Ваш код для регистрации: ${code}`);

        res.json({ message: 'Код отправлен на почту!' });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера: ' + err.message }); }
});

app.post('/api/verify', async (req, res) => {
    try {
        const { email, code } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1 AND verify_code = $2', [email, code]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Неверный код' });
        
        const user = result.rows[0];
        await pool.query('UPDATE users SET is_verified = TRUE, verify_code = NULL WHERE id = $1', [user.id]);
        
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ message: 'Почта подтверждена!', token, username: user.username });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0 || !result.rows[0].is_verified) return res.status(400).json({ error: 'Неверный email или пароль' });
        
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ error: 'Неверный пароль' });
        
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '30d' });
        res.json({ message: 'Успешный вход!', token, username: user.username });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/forgot-password', async (req, res) => {
    try {
        const { email } = req.body;
        const result = await pool.query('SELECT id FROM users WHERE email = $1 AND is_verified = TRUE', [email]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Аккаунт не найден' });
        
        const code = generateCode();
        const expires = Date.now() + 15 * 60 * 1000;
        await pool.query('UPDATE users SET reset_code = $1, reset_expires = $2 WHERE id = $3', [code, expires, result.rows[0].id]);
        
        console.log(`\n=========================================`);
        console.log(`🔑 КОД СБРОСА ПАРОЛЯ ДЛЯ ${email}: [ ${code} ]`);
        console.log(`=========================================\n`);

        sendEmail(email, 'Сброс пароля GD Review', `Ваш код для сброса пароля: ${code}`);
        res.json({ message: 'Код отправлен!' });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/reset-password', async (req, res) => {
    try {
        const { email, code, newPassword } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1 AND reset_code = $2', [email, code]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Неверный код' });
        if (Date.now() > result.rows[0].reset_expires) return res.status(400).json({ error: 'Код истек' });
        
        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(newPassword, salt);
        await pool.query('UPDATE users SET password_hash = $1, reset_code = NULL, reset_expires = NULL WHERE id = $2', [passwordHash, result.rows[0].id]);
        res.json({ message: 'Пароль успешно изменен!' });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/change-password', authenticateToken, async (req, res) => {
    try {
        const { oldPassword, newPassword } = req.body;
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
        const isMatch = await bcrypt.compare(oldPassword, result.rows[0].password_hash);
        if (!isMatch) return res.status(400).json({ error: 'Неверный текущий пароль' });
        
        const salt = await bcrypt.genSalt(10);
        const hash = await bcrypt.hash(newPassword, salt);
        await pool.query('UPDATE users SET password_hash = $1 WHERE id = $2', [hash, req.user.userId]);
        res.json({ message: 'Пароль изменен!' });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/change-email', authenticateToken, async (req, res) => {
    try {
        const { password, newEmail } = req.body;
        const result = await pool.query('SELECT password_hash FROM users WHERE id = $1', [req.user.userId]);
        const isMatch = await bcrypt.compare(password, result.rows[0].password_hash);
        if (!isMatch) return res.status(400).json({ error: 'Неверный пароль' });
        
        const emailCheck = await pool.query('SELECT id FROM users WHERE email = $1', [newEmail]);
        if (emailCheck.rows.length > 0) return res.status(400).json({ error: 'Почта уже занята' });

        await pool.query('UPDATE users SET email = $1 WHERE id = $2', [newEmail, req.user.userId]);
        res.json({ message: 'Почта успешно изменена!' });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.delete('/api/account', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM reviews WHERE user_id = $1', [req.user.userId]);
        await pool.query('DELETE FROM users WHERE id = $1', [req.user.userId]);
        res.json({ message: 'Аккаунт удален' });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ==========================================
// 2. ПРОФИЛЬ И ОБЗОРЫ
// ==========================================
app.get('/api/profile', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT username, avatar, banner, frame, description, socials FROM users WHERE id = $1', [req.user.userId]);
        if (result.rows.length > 0) res.json(result.rows[0]);
        else res.status(404).json({error: 'Not found'});
    } catch(err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/profile', authenticateToken, async (req, res) => {
    try {
        let { avatar, banner, frame, description, socials } = req.body;
        avatar = await uploadToCloud(avatar);
        banner = await uploadToCloud(banner);
        await pool.query(`UPDATE users SET avatar = $1, banner = $2, frame = $3, description = $4, socials = $5 WHERE id = $6`, 
            [avatar, banner, frame, description, socials, req.user.userId]);
        res.json({ message: 'Профиль сохранен' });
    } catch(err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.get('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM reviews WHERE user_id = $1 ORDER BY saved_at DESC', [req.user.userId]);
        res.json(result.rows);
    } catch(err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { level_id, level_name, level_author, difficulty, difficulty_face, stars, ratings, finalScore, text } = req.body;
        const existing = await pool.query('SELECT id FROM reviews WHERE user_id = $1 AND level_id = $2', [req.user.userId, level_id]);
        if (existing.rows.length > 0) {
            await pool.query(`UPDATE reviews SET gameplay=$1, flow=$2, decoration=$3, music=$4, originality=$5, optimization=$6, final_score=$7, review_text=$8, saved_at=CURRENT_TIMESTAMP WHERE id=$9`, 
                [ratings.gameplay, ratings.flow, ratings.decoration, ratings.music, ratings.originality, ratings.optimization, finalScore, text, existing.rows[0].id]);
            return res.json({ message: 'Обзор обновлен' });
        } else {
            await pool.
