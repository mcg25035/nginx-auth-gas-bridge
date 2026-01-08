process.loadEnvFile();

const http = require('http');
const https = require('https');

const GAS_URL = process.env.GAS_URL;
const PORT = process.env.PORT || 3000;
const BIND_IP = process.env.BIND_IP || '127.0.0.1';

const server = http.createServer(async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
        res.statusCode = 401;
        res.setHeader('WWW-Authenticate', 'Basic realm="GAS Auth Bridge"');
        return res.end('401 Authorization Required');
    }

    const b64auth = authHeader.split(' ')[1];
    const [user, token] = Buffer.from(b64auth, 'base64').toString().split(':');

    if (!token) {
        res.statusCode = 401;
        return res.end('Token missing');
    }

    try {
        const gasResponse = await fetch(GAS_URL, {
            method: 'POST',
            redirect: 'follow', 
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: token })
        });

        const data = await gasResponse.json();

        if (data.pass === true) {
            console.log(`Token ${token} verified: PASS`);
            res.statusCode = 200; 
        } else {
            console.log(`Token ${token} verified: FAIL`);
            res.statusCode = 401; 
        }
    } catch (error) {
        console.error("GAS Error:", error);
        res.statusCode = 401; 
    }
    
    res.end();
});

server.listen(PORT, BIND_IP, () => {
    console.log(`Auth Bridge running on ${BIND_IP}:${PORT}`);
});