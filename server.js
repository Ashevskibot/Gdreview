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

    // Маскируем наш сервер под обычный браузер Google Chrome
    const options = {
        headers: {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://www.newgrounds.com/',
            'Accept': '*/*'
        }
    };

    const fetchAudio = (urlToFetch) => {
        https.get(urlToFetch, options, (proxyRes) => {
            // Если Newgrounds перенаправляет на другую ссылку
            if (proxyRes.statusCode >= 300 && proxyRes.statusCode < 400 && proxyRes.headers.location) {
                return fetchAudio(proxyRes.headers.location);
            }
            
            // Передаем музыку пользователю вместе с оригинальными заголовками
            res.writeHead(proxyRes.statusCode, proxyRes.headers);
            proxyRes.pipe(res);
        }).on('error', (err) => {
            console.error('Ошибка загрузки трека:', err);
            if (!res.headersSent) res.status(500).send('Ошибка');
        });
    };

    fetchAudio(audioUrl);
});

app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, () => {
    console.log(`Сервер запущен на порту ${PORT}`);
});
