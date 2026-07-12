const express = require('express');
const path = require('path');
const https = require('https');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = 'gd_review_super_secret_key'; // Секретный ключ для сессий

// Подключаемся к базе данных
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Создаем таблицы для юзеров и их обзоров
pool.connect()
    .then(() => {
        console.log('✅ Подключились к базе данных PostgreSQL!');
        return pool.query(`
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
                gameplay INTEGER,
                flow INTEGER,
                decoration INTEGER,
                music INTEGER,
                originality INTEGER,
                optimization INTEGER,
                final_score NUMERIC(4,2),
                review_text TEXT,
                saved_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
    })
    .then(() => console.log('✅ Таблицы готовы к работе!'))
    .catch(err => console.error('❌ Ошибка базы данных:', err.stack));

app.use(express.json()); 
app.use(express.static(path.join(__dirname, 'public')));

// === ФИЛЬТР БЕЗОПАСНОСТИ (Middleware) ===
// Эта функция проверяет, вошел ли пользователь в аккаунт перед тем, как дать ему сохранить обзор
const authenticateToken = (req, res, next) => {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(' ')[1];
    if (!token) return res.status(401).json({ error: 'Необходима авторизация' });

    jwt.verify(token, JWT_SECRET, (err, user) => {
        if (err) return res.status(403).json({ error: 'Сессия истекла, войдите заново' });
        req.user = user;
        next();
    });
};

// ==========================================
// 1. АВТОРИЗАЦИЯ
// ==========================================
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (userExists.rows.length > 0) return res.status(400).json({ error: 'Email или никнейм уже занят' });

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );

        const token = jwt.sign({ userId: newUser.rows[0].id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Успех!', token, username });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Пользователь не найден' });
        
        const user = result.rows[0];
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ error: 'Неверный пароль' });
        
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Успешный вход!', token, username: user.username });
    } catch (err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ==========================================
// 2. СОХРАНЕНИЕ И ЗАГРУЗКА ОБЗОРОВ
// ==========================================
// Загрузить все обзоры пользователя
app.get('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const result = await pool.query('SELECT * FROM reviews WHERE user_id = $1 ORDER BY saved_at DESC', [req.user.userId]);
        res.json(result.rows);
    } catch(err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// Сохранить или обновить обзор
app.post('/api/reviews', authenticateToken, async (req, res) => {
    try {
        const { level_id, level_name, level_author, difficulty, difficulty_face, stars, ratings, finalScore, text } = req.body;
        
        // Проверяем, оценивал ли юзер этот уровень ранее
        const existing = await pool.query('SELECT id FROM reviews WHERE user_id = $1 AND level_id = $2', [req.user.userId, level_id]);
        
        if (existing.rows.length > 0) {
            // Если да — перезаписываем
            await pool.query(`
                UPDATE reviews SET gameplay=$1, flow=$2, decoration=$3, music=$4, originality=$5, optimization=$6, final_score=$7, review_text=$8, saved_at=CURRENT_TIMESTAMP
                WHERE id=$9
            `, [ratings.gameplay, ratings.flow, ratings.decoration, ratings.music, ratings.originality, ratings.optimization, finalScore, text, existing.rows[0].id]);
            return res.json({ message: 'Обзор обновлен' });
        } else {
            // Если нет — создаем новый
            await pool.query(`
                INSERT INTO reviews (user_id, level_id, level_name, level_author, difficulty, difficulty_face, stars, gameplay, flow, decoration, music, originality, optimization, final_score, review_text)
                VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
            `, [req.user.userId, level_id, level_name, level_author, difficulty, difficulty_face, stars, ratings.gameplay, ratings.flow, ratings.decoration, ratings.music, ratings.originality, ratings.optimization, finalScore, text]);
            return res.json({ message: 'Обзор сохранен' });
        }
    } catch(err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// Удалить обзор
app.delete('/api/reviews/:id', authenticateToken, async (req, res) => {
    try {
        await pool.query('DELETE FROM reviews WHERE id = $1 AND user_id = $2', [req.params.id, req.user.userId]);
        res.json({ message: 'Удалено' });
    } catch(err) { res.status(500).json({ error: 'Ошибка сервера' }); }
});

// ==========================================
// 3. ПРОКСИ ДЛЯ МУЗЫКИ (оставили как было)
// ==========================================
app.get('/api/audio', (req, res) => {
    const audioUrl = req.query.url;
    if (!audioUrl) return res.status(400).send('URL не указан');
    const options = { headers: { 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36', 'Referer': 'https://www.newgrounds.com/', 'Accept': '*/*' } };
    const fetchAudio = (urlToFetch) => {
        https.get(urlToFetch, options, (proxyRes) => {
            if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) return fetchAudio(proxyRes.headers.location);
            res.writeHead(proxyRes.statusCode, proxyRes.headers); proxyRes.pipe(res);
        }).on('error', (err) => { if (!res.headersSent) res.status(500).send('Ошибка'); });
    };
    fetchAudio(audioUrl);
});

app.get('*', (req, res) => { res.sendFile(path.join(__dirname, 'public', 'index.html')); });
app.listen(PORT, () => { console.log(`🚀 Сервер запущен на порту ${PORT}`); });
