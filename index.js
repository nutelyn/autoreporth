const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { formatLogs, ceefFormatLogs } = require('./parsing.js');
const { auth } = require('./auth.js');

const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

app.use(express.static(path.join(__dirname, 'views')));

app.get('/', auth, (req, res) => {
    res.render('index');
});

app.get('/mandoloqr', (req, res) => {
    res.render('mandoloqradar', { formattedText: null });
});

app.post('/mandoloqr', (req, res) => {
    const inputText = req.body.text;
    let predef =
        `Dear Team Mandala,\nBerikut kami laporkan mengenai aktivitas berdasarkan log monitoring SIEM last 6H.`;
    let formatted = formatLogs(inputText);
    res.render('mandoloqradar', { formattedText: `${predef}\n${formatted}` });
});

app.get('/ceefwaf', (req, res) => {
    res.render('ceefwaf', { formattedText: null });
});

app.post('/ceefwaf', (req, res) => {
    const inputText = req.body.text;
    let salam = '';
    let predef = ``;
    let formatted = ceefFormatLogs(inputText);
    res.render('ceefwaf', {formattedText: null });
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
