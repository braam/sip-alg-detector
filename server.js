const dgram = require('dgram');
const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

// CONFIGURATION
const SIP_UDP_PORTS = [5060, 6060, 5678, 6050];
const SIP_TLS_PORTS = [5061, 6061];
const RTP_PORTS = [30000, 30001, 30002, 50000];

/**
 * 1. SSL CERTIFICATE AUTOMATION
 */
function ensureCertificates() {
    if (!fs.existsSync('key.pem') || !fs.existsSync('cert.pem')) {
        console.log("[INFO] Generating self-signed certificates...");
        try {
            execSync(`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=SipAlgTestServer"`);
        } catch (err) {
            console.error("[ERROR] OpenSSL failed. Ensure it is installed.");
            process.exit(1);
        }
    }
}
ensureCertificates();
const tlsOptions = { key: fs.readFileSync('key.pem'), cert: fs.readFileSync('cert.pem') };

/**
 * 2. TLS & RTP SERVICES
 */
SIP_TLS_PORTS.forEach(port => {
    https.createServer(tlsOptions, (req, res) => {
        console.log(`[TLS] Request on port ${port} from ${req.socket.remoteAddress}`);
        res.writeHead(200); res.end("OK");
    }).listen(port, () => console.log(`[OK] TLS Service port ${port}`));
});

RTP_PORTS.forEach(port => {
    const rtpSocket = dgram.createSocket('udp4');
    rtpSocket.on('message', (msg, rinfo) => {
        if (msg.length <= 1500) rtpSocket.send(msg, rinfo.port, rinfo.address);
    });
    rtpSocket.bind(port, () => console.log(`[OK] RTP Echo port ${port}`));
});

/**
 * 3. SECURE SIP UDP SERVICE (STEALTH MODE)
 */
SIP_UDP_PORTS.forEach(port => {
    const sipSocket = dgram.createSocket('udp4');

    sipSocket.on('message', (msg, rinfo) => {
        // A. OVERFLOW PROTECTION
        if (msg.length > 2000) return;

        const rawMsg = msg.toString('utf8', 0, 2000);

        // Helper function for safe header parsing
        const getHeader = (name) => {
            const regex = new RegExp(`^${name}:\\s*([^\\r\\n]{0,500})`, 'im');
            const match = rawMsg.match(regex);
            return match ? match[1].trim() : null;
        };

        // B. SECURITY: VALID CLIENT CHECK (STEALTH MODE)
        // If the custom P-AL-SA header is missing, we drop the packet immediately.
        const pAlSaRaw = getHeader('P-AL-SA');
        if (!pAlSaRaw) return; 

        // C. SIP LOGIC
        const callId = getHeader('Call-ID');
        if (!callId) return;

        console.log(`[UDP] Valid SIP Data on port ${port} from ${rinfo.address}:${rinfo.port}`);

        const clientLocalInfo = pAlSaRaw.replace(/\*/g, '.').replace('#', ':');
        const via = getHeader('Via');
        
        // D. IMPROVED DETECTION: Compare Via with original local IP
        let algDetected = false;
        if (via && clientLocalInfo) {
            const localIpOnly = clientLocalInfo.split(':')[0];
            if (!via.includes(localIpOnly)) {
                algDetected = true;
            }
        }

        const result = algDetected ? "Failed. SIP ALG Detected" : "Pass";
        console.log(`      -> Result: ${result} | Client: ${clientLocalInfo}`);

        const response = 
            `SIP/2.0 200 OK\r\n` +
            `Via: ${via}\r\n` +
            `From: ${getHeader('From')}\r\n` +
            `To: ${getHeader('To')}\r\n` +
            `Call-ID: ${callId}\r\n` +
            `CSeq: ${getHeader('CSeq')}\r\n` +
            `p-al-result: ${result}\r\n` +
            `p-al-sa: ${(`${rinfo.address}#${rinfo.port}`).replace(/\./g, '*')}\r\n` +
            `Content-Length: 0\r\n\r\n`;

        const delaySec = parseInt(getHeader('P-AL-Delay')) || 0;
        setTimeout(() => {
            sipSocket.send(response, rinfo.port, rinfo.address);
        }, delaySec * 1000);
    });

    sipSocket.bind(port, () => console.log(`[OK] SIP Service port ${port}`));
});
