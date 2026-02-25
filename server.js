const dgram = require('dgram');
const https = require('https');
const fs = require('fs');
const { execSync } = require('child_process');

const SIP_UDP_PORTS = [5060, 6060, 5678, 6050];
const SIP_TLS_PORTS = [5061, 6061];
const RTP_PORTS = [30000, 30001, 30002, 50000];

// 1. SSL Setup
function ensureCertificates() {
    if (!fs.existsSync('key.pem') || !fs.existsSync('cert.pem')) {
        console.log("[INFO] Generating certificates...");
        execSync(`openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes -subj "/CN=SipAlgTestServer"`);
    }
}
ensureCertificates();
const tlsOptions = { key: fs.readFileSync('key.pem'), cert: fs.readFileSync('cert.pem') };

// 2. TLS/RTP (Remains the same...)
SIP_TLS_PORTS.forEach(port => {
    https.createServer(tlsOptions, (req, res) => {
        console.log(`[TLS] Request on port ${port} from ${req.socket.remoteAddress}`);
        res.writeHead(200); res.end("OK");
    }).listen(port);
});

RTP_PORTS.forEach(port => {
    const rtpSocket = dgram.createSocket('udp4');
    rtpSocket.on('message', (msg, rinfo) => {
        rtpSocket.send(msg, rinfo.port, rinfo.address);
    });
    rtpSocket.bind(port);
});

// 3. SIP UDP with Fixed Detection & Overflow Protection
SIP_UDP_PORTS.forEach(port => {
    const sipSocket = dgram.createSocket('udp4');

    sipSocket.on('message', (msg, rinfo) => {
        // OVERFLOW PROTECTION: Drop packets > 2000 bytes
        if (msg.length > 2000) return;

        const rawMsg = msg.toString('utf8', 0, 2000);
        console.log(`[UDP] SIP Data on port ${port} from ${rinfo.address}:${rinfo.port}`);

        if (rawMsg.trim().length === 0) {
            sipSocket.send("\r\n\r\n", rinfo.port, rinfo.address);
            return;
        }

        const getHeader = (name) => {
            const regex = new RegExp(`^${name}:\\s*([^\\r\\n]{0,500})`, 'im');
            const match = rawMsg.match(regex);
            return match ? match[1].trim() : null;
        };

        const callId = getHeader('Call-ID');
        if (!callId) return;

        const pAlSaRaw = getHeader('P-AL-SA');
        const clientLocalInfo = pAlSaRaw ? pAlSaRaw.replace(/\*/g, '.').replace('#', ':') : null;
        const via = getHeader('Via');
        
        // FIXED DETECTION: Compare Via with P-AL-SA
        let algDetected = false;
        if (via && clientLocalInfo) {
            if (!via.includes(clientLocalInfo.split(':')[0])) { // Check IP only
                algDetected = true;
            }
        }

        const result = algDetected ? "Failed. SIP ALG Detected" : "Pass";
        console.log(`      -> Result: ${result} | Via: ${via ? via.substring(0, 40) : 'N/A'} | P-AL-SA: ${clientLocalInfo}`);

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
