const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { formatLogs, ceefFormatLogs, greetTime } = require('./parsing.js');
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

app.get('/mandoloqr', checkCookieAuth, (req, res) => {
    res.render('mandoloqradar', { formattedText: null });
});

app.post('/mandoloqr', checkCookieAuth, (req, res) => {
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
    let salam = greetTime();
    let formatted = ceefFormatLogs(inputText);
    res.render('ceefwaf', {formattedText: `${salam}\n\n${formatted}` });
});


app.get('/mandoloip', checkCookieAuth, (req, res) => {
    res.render('mandoloip', { formattedText: null });
});

app.post('/mandoloip', checkCookieAuth, async (req, res) => {
    const inputText = req.body.text;
    const predefTop = 'Dalam 6 jam terakhir kami menemukan adanya IP eksternal yang mencurigakan berikut:';
    const predefBot = 'Kami sarankan untuk blok IP yang terindikasi mencurigakan\nTerima kasih.'
    try {
        const formattedIPs = await formatIP(inputText); // comment when developing or remove the key in parsing.js:41 (expect some errors)
        const outputText = formattedIPs.join('\n');
        res.render('mandoloip', { formattedText: `${predefTop}\n\n${outputText}\n${predefBot}` });
    } catch (error) {
        console.error('Error processing IPs:', error);
        res.status(500).send('An error occurred while processing the request.');
    }
});

app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
