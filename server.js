const express = require('express');
const path = require('path');
const https = require('https');
const { Pool } = require('pg'); // Подключаем библиотеку базы данных

const app = express();
const PORT = process.env.PORT || 3000;

// Подключаемся к базе данных PostgreSQL, которую создал Railway
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
});

// Проверяем, работает ли подключение к базе
pool.connect()
    .then(() => console.log('✅ Успешно подключились к базе данных PostgreSQL!'))
    .catch(err => console.error('❌ Ошибка подключения к базе:', err.stack));

// Чтобы сервер понимал данные, которые мы будем отправлять при регистрации
app.use(express.json()); 
app.use(express.static(path.join(__dirname, 'public')));

// Наш прокси для музыки (оставляем как есть)
app.get('/api/audio', (req, res) => {
    const audioUrl = req.query.url;
    if (!audioUrl) return res.status(400).send('URL не указан');

    const options = {
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0 Safari/537.36',
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

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`🚀 Сервер запущен на порту ${PORT}`);
});
