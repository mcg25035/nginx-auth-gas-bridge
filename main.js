const http = require('http');

const GAS_URL = process.env.GAS_URL;
// 建議設定：如果是開發環境可以縮短 TTL，生產環境維持 300
const CACHE_TTL = (process.env.CACHE_TTL || 300) * 1000;

const tokenCache = new Map();
const pendingRequests = new Map();

const server = http.createServer(async (req, res) => {
    console.log(req.headers)

    const authHeader = req.headers.authorization;
    if (!authHeader) { res.statusCode = 401; return res.end(); }

    const b64auth = authHeader.split(' ')[1];
    
    const [user, token] = Buffer.from(b64auth, 'base64').toString().split(':');
    const ip = req.headers['cf-connecting-ip'] || req.socket.remoteAddress;
    const refer = req.headers['referer'] || '';

    
    const requiredRoles = req.headers['x-required-groups'] || '';

    if (!token) { res.statusCode = 401; return res.end(); }

    
    const cacheKey = `${token}|${requiredRoles}`;
    
    const cachedRecord = tokenCache.get(cacheKey);
    const now = Date.now();

    if (cachedRecord) {
        if (now - cachedRecord.timestamp < CACHE_TTL) {
            console.log(`[Cache Hit] Token: ${token.substring(0, 5)}... Role: [${requiredRoles}] Result: ${cachedRecord.pass ? 'PASS' : 'FAIL'}`);
            res.statusCode = cachedRecord.pass ? 200 : 401;
            return res.end();
        } else {
            tokenCache.delete(cacheKey);
        }
    }

    
    let fetchPromise = pendingRequests.get(cacheKey);

    if (!fetchPromise) {
        console.log(`[GAS Fetch] Verifying Token: ${token.substring(0, 5)}... Role: [${requiredRoles}]`);

        fetchPromise = fetch(GAS_URL, {
            method: 'POST',
            redirect: 'follow',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ 
                token: token, 
                ip: ip,
                role: requiredRoles,
                refer: refer 
            })
        })
        .then(async (response) => {
            const data = await response.json();
            const isPass = (data.pass === true);
            
            tokenCache.set(cacheKey, {
                pass: isPass,
                timestamp: Date.now()
            });
            return isPass;
        })
        .catch(err => {
            console.error("Fetch Error:", err);
            return false; 
        })
        .finally(() => {
            pendingRequests.delete(cacheKey);
        });

        pendingRequests.set(cacheKey, fetchPromise);
    }

    try {
        const isPass = await fetchPromise;
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