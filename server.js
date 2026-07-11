const express = require('express');
const path = require('path');
const https = require('https'); // Добавляем модуль для скачивания из интернета

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.static(path.join(__dirname, 'public')));

// Наш собственный прокси для музыки с Newgrounds
app.get('/api/audio', (req, res) => {
    const audioUrl = req.query.url;
    if (!audioUrl) return res.status(400).send('URL не указан');

    https.get(audioUrl, (proxyRes) => {
        // Проверяем, нет ли перенаправлений (Newgrounds иногда так делает)
        if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
            return https.get(proxyRes.headers.location, (redirectRes) => {
                res.writeHead(redirectRes.statusCode, redirectRes.headers);
                redirectRes.pipe(res);
            });
        }
        // Передаем музыку пользователю
        res.writeHead(proxyRes.statusCode, proxyRes.headers);
        proxyRes.pipe(res);
    }).on('error', (err) => {
        console.error('Ошибка загрузки трека:', err);
        res.status(500).send('Ошибка');
    });
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
