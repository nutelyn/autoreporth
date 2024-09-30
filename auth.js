const express = require('express');
const basicAuth = require('basic-auth');
const crypto = require('crypto');

const app = express();
function md5Hash(str) {
    return crypto.createHash('md5').update(str).digest('hex');
}

function auth(req, res, next) {
    const user = basicAuth(req);

    const uname = 'dege';
    const passw = '108d8ea12261d42767f29e8739fd0c34'

    if (user && user.name === uname && md5Hash(user.pass) === passw) {
        return next();
    }

    res.set('WWW-Authenticate', 'basic realm="Nuts-Domain"');
    return res.status(401).send('no wae you got no access, u must be heker');
}

module.exports = { auth };

