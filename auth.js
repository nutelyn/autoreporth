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
    const passw = '108d8ea12261d42767f29e8739fd0c34';

    if (req.cookies && req.cookies.authToken) {
        return next();
    }

    if (user && user.name === uname && md5Hash(user.pass) === passw) {
        res.cookie('authToken', 'af11cdaaba25a1fb8dacae471c083d2b', { maxAge: 900000, httpOnly: true }); // cookie valid for 15 minutes only, no staying here
        return next();
    }

    res.set('WWW-Authenticate', 'basic realm="Nuts-Domain"');
    return res.status(401).send('no wae you got no access, u must be heker');
}

function checkCookieAuth(req, res, next) {
    if (req.cookies && req.cookies.authToken === 'authenticated') {
        return next();
    }

    return res.redirect('/');
}

module.exports = { auth, checkCookieAuth };

