const http = require('http');


const GAS_URL = "https://script.google.com/macros/s/AKfycbzKkU8-w86Y4RDO3LUiS4dSP8v0d_rZq9XrrQUEQUBzy8Rz-3Z7HqVQ6ti6E-Tdsza1hA/exec";

const CACHE_TTL = 300 * 1000;

const tokenCache = new Map();

const server = http.createServer(async (req, res) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) { res.statusCode = 401; return res.end(); }

    const b64auth = authHeader.split(' ')[1];
    const [user, token] = Buffer.from(b64auth, 'base64').toString().split(':');
    const ip = req.headers['cf-connecting-ip'];

    if (!token) { res.statusCode = 401; return res.end(); }

    const cachedRecord = tokenCache.get(token);
    const now = Date.now();

    if (cachedRecord) {
        if (now - cachedRecord.timestamp < CACHE_TTL) {
            console.log(`[Cache Hit] Token: ${token.substring(0, 5)}... Result: ${cachedRecord.pass ? 'PASS' : 'FAIL'}`);
            res.statusCode = cachedRecord.pass ? 200 : 401;
            return res.end();
        } else {
            tokenCache.delete(token);
        }
    }

    console.log(`[GAS Fetch] Verifying Token: ${token.substring(0, 5)}...`);

    try {
        const gasResponse = await fetch(GAS_URL, {
            method: 'POST',
            redirect: 'follow',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ token: token, ip: ip })
        });

        const data = await gasResponse.json();
        const isPass = (data.pass === true);

        tokenCache.set(token, {
            pass: isPass,
            timestamp: now
        });

        if (isPass) {
            res.statusCode = 200;
        } else {
            res.statusCode = 401;
        }

    } catch (error) {
        console.error("GAS Error:", error);
        res.statusCode = 401;
    }

    res.end();
});

setInterval(() => {
    const now = Date.now();
    for (const [key, value] of tokenCache.entries()) {
        if (now - value.timestamp > CACHE_TTL * 2) {
            tokenCache.delete(key);
        }
    }
}, 10 * 60 * 1000);

server.listen(3000, () => {
    console.log('Auth Bridge with Cache running on port 3000');
});
