const express = require('express');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;

// Говорим серверу отдавать файлы из папки public
app.use(express.static(path.join(__dirname, 'public')));

// Если кто-то просто заходит на сайт, показываем ему index.html
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Запускаем сервер
app.listen(PORT, () => {
    console.log(`Сервер запущен и слушает порт ${PORT}`);
});
