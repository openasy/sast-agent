const https = require("https");
// ruleid: openasy.javascript.tls-verification-off
const agent = new https.Agent({ keepAlive: true, rejectUnauthorized: false });
// ruleid: openasy.javascript.tls-verification-off
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";
// ok: openasy.javascript.tls-verification-off
const safe = new https.Agent({ rejectUnauthorized: true });
