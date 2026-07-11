const express = require('express');
const path = require('path');
const https = require('https');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs'); // Библиотека для шифрования паролей
const jwt = require('jsonwebtoken'); // Библиотека для сессий

const app = express();
const PORT = process.env.PORT || 3000;

// Подключаемся к базе данных
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Автоматически создаем таблицы при запуске сервера
pool.connect()
    .then(() => {
        console.log('✅ Успешно подключились к базе данных PostgreSQL!');
        // Создаем таблицу пользователей (если её еще нет)
        return pool.query(`
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(100) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);
    })
    .then(() => console.log('✅ Таблицы в базе данных готовы к работе!'))
    .catch(err => console.error('❌ Ошибка базы данных:', err.stack));

// Настройки сервера
app.use(express.json()); 
app.use(express.static(path.join(__dirname, 'public')));

// ==========================================
// 1. СИСТЕМА АВТОРИЗАЦИИ (API)
// ==========================================
const JWT_SECRET = 'gd_review_super_secret_key'; // Ключ для защиты сессий

// Регистрация
app.post('/api/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        
        const userExists = await pool.query('SELECT * FROM users WHERE email = $1 OR username = $2', [email, username]);
        if (userExists.rows.length > 0) {
            return res.status(400).json({ error: 'Пользователь с таким email или никнеймом уже существует' });
        }

        const salt = await bcrypt.genSalt(10);
        const passwordHash = await bcrypt.hash(password, salt);

        const newUser = await pool.query(
            'INSERT INTO users (username, email, password_hash) VALUES ($1, $2, $3) RETURNING id, username, email',
            [username, email, passwordHash]
        );

        // Выдаем "билет" (токен) на 7 дней
        const token = jwt.sign({ userId: newUser.rows[0].id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Успешная регистрация!', token, username });
    } catch (err) {
        console.error('Ошибка при регистрации:', err.message);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// Вход (Логин)
app.post('/api/login', async (req, res) => {
    try {
        const { email, password } = req.body;
        
        const result = await pool.query('SELECT * FROM users WHERE email = $1', [email]);
        if (result.rows.length === 0) return res.status(400).json({ error: 'Пользователь не найден' });
        
        const user = result.rows[0];
        // Проверяем пароль
        const isMatch = await bcrypt.compare(password, user.password_hash);
        if (!isMatch) return res.status(400).json({ error: 'Неверный пароль' });
        
        // Выдаем "билет"
        const token = jwt.sign({ userId: user.id }, JWT_SECRET, { expiresIn: '7d' });
        res.json({ message: 'Успешный вход!', token, username: user.username });
    } catch (err) {
        console.error('Ошибка при входе:', err.message);
        res.status(500).json({ error: 'Внутренняя ошибка сервера' });
    }
});

// ==========================================
// 2. ПРОКСИ ДЛЯ МУЗЫКИ (Оставили как было)
// ==========================================
app.get('/api/audio', (req, res) => {
    const audioUrl = req.query.url;
    if (!audioUrl) return res.status(400).send('URL не указан');

    const options = {
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://www.newgrounds.com/',
            'Accept': '*/*'
        }
    };

    const fetchAudio = (urlToFetch) => {
        https.get(urlToFetch, options, (proxyRes) => {
            if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
                return fetchAudio(proxyRes.headers.location);
            }
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res);
        }).on('error', (err) => {
            if (!res.headersSent) res.status(500).send('Ошибка');
        });
    };
    fetchAudio(audioUrl);
});

// Отдаем сайт при любом запросе
app.get('*', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запуск
app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
