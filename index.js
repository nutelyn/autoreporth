const express = require('express');
const path = require('path');
const bodyParser = require('body-parser');
const { formatLogs, ceefFormatLogs, greetTime, formatIP, stormwallLogs, networkLogs } = require('./parsing.js');
const { auth } = require('./auth.js');
const { fetchBGPAPI, cacheDiff, getCacheExp } = require('./BGPutils.js');

const app = express();
const PORT = 3000;

app.use(bodyParser.urlencoded({ extended: true }));

app.set('views', path.join(__dirname, 'views'));
app.use(express.static(path.join(__dirname, 'views')));
app.set('view engine', 'ejs');

app.get('/', auth, (req, res) => {
    res.render('index');
});

// mandolo qradar log parse
app.get('/mandoloqr', (req, res) => {
    res.render('mandoloqradar', { formattedText: null });
});

app.post('/mandoloqr', (req, res) => {
    const inputText = req.body.text;
    let predef =
        `Dear Team Mandala,\nBerikut kami laporkan mengenai aktivitas berdasarkan log monitoring SIEM last 6H.`;
    let formatted = formatLogs(inputText);
    res.render('mandoloqradar', { formattedText: `${predef}\n${formatted}\nTerima Kasih` });
});

// mandolo ip parse
app.get('/mandoloip', (req, res) => {
    res.render('mandoloip', { formattedText: null });
});

app.post('/mandoloip', async (req, res) => {
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

// cloudflare parse
app.get('/ceefwaf', (req, res) => {
    res.render('ceefwaf', { formattedText: null });
});

app.post('/ceefwaf', (req, res) => {
    const inputText = req.body.text;
    let salam = greetTime();
    let formatted = ceefFormatLogs(inputText);
    res.render('ceefwaf', { formattedText: `${salam}\n\n${formatted}` });
});

// stormwall parse
app.get('/stormwall', (req, res) => {
    res.render('stormwall', { formattedText: null });
});

app.post('/stormwall', (req, res) => {
    const inputText = req.body.text;
    let salam = greetTime();
    let formatted = stormwallLogs(inputText);
    res.render('stormwall', { formattedText: `${salam}\n\n${formatted}` });
});

/* network parsing */
app.get('/network', async (req, res) => {

    let networkData;
    if (getCacheExp()) {
        networkData = await fetchBGPAPI(getCacheExp);
        app.locals.networkData = networkData;
    } else {
        networkData = app.locals.networkData;
    }

    let timestamp = cacheDiff();
    
    try {

        // Render the network page
        res.render('network', { formattedText: null, tableData: networkData, prevTimestamp: timestamp });
    } catch (error) {
        console.error('Error assigning local network data:', error.message);
        res.status(500).send('Error assigning local network data');
    }

});

app.get('/bgpapi', async (req, res) => {
    try {

        // Fetch the data (either from cache or fresh data)
        console.log("Fetching BGP API data...");
        networkData = await fetchBGPAPI(false);
        console.log("BGP API data fetched successfully!");

        app.locals.networkData = networkData;

        res.redirect('network');

    } catch (error) {
        console.error('Error fetching network data:', error.message);
        res.status(500).send('Error loading network data');
    }
});

app.get('/getnew', async (req, res) => {
    try {

        // Fetch the data (either from cache or fresh data)
        console.log("Fetching BGP API data...");
        networkData = await fetchBGPAPI(true);
        console.log("BGP API data fetched successfully!");

        app.locals.networkData = networkData;

        res.redirect('network');

    } catch (error) {
        console.error('Error fetching network data:', error.message);
        res.status(500).send('Error loading network data');
    }
});

app.post('/network', async (req, res) => {

    // Get the selection
    let selection = req.body.selection;
    
    let networkData = app.locals.networkData;

    let timestamp = cacheDiff();
    
    if (!networkData || selection === "None") {
        res.redirect('network');
    } else {
        let formatted = networkLogs(selection, networkData);
        res.render('network', { formattedText: formatted, tableData: networkData, prevTimestamp: timestamp });
    }
});

// Run the server
app.listen(PORT, () => {
    console.log(`Server running at http://localhost:${PORT}`);
});


    