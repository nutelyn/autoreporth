const express = require('express');
const path = require('path');
const bodyParser = require('body-parser'); // To handle form data
const { formatLogs } = require('./parsing.js');

const app = express();
const PORT = 3000;

// Middleware to handle URL-encoded form data
app.use(bodyParser.urlencoded({ extended: true }));

// Set the views directory and use EJS for templating
app.set('views', path.join(__dirname, 'views'));
app.set('view engine', 'ejs');

// Serve static HTML files from the views directory
app.use(express.static(path.join(__dirname, 'views')));

// Render the form page on the root URL
app.get('/', (req, res) => {
    res.render('index', { formattedText: null });
});

// Handle form submission and encode the text to Base64
app.post('/', (req, res) => {
    const inputText = req.body.text;
    let predef =
        `Dear Team Mandala,\nBerikut kami laporkan mengenai aktivitas berdasarkan log monitoring SIEM last 6H.`;
    let formatted = formatLogs(inputText);
    // Render the page again, now including the encoded text
    res.render('index', { formattedText: `${predef}\n${formatted}` });
});

// Start the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});
