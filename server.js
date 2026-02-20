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
    const keyFile = 'key.pem';
    const certFile = 'cert.pem';

    if (!fs.existsSync(keyFile) || !fs.existsSync(certFile)) {
        console.log("[INFO] Certificates not found. Generating new self-signed certificates...");
        try {
            execSync(`openssl req -x509 -newkey rsa:4096 -keyout ${keyFile} -out ${certFile} -days 365 -nodes -subj "/CN=SipAlgTestServer"`, { stdio: 'inherit' });
            console.log("[OK] Certificates generated successfully.");
        } catch (err) {
            console.error("[ERROR] Failed to execute openssl. Ensure openssl is installed.");
            process.exit(1);
        }
    }
}

ensureCertificates();

const tlsOptions = {
    key: fs.readFileSync('key.pem'),
    cert: fs.readFileSync('cert.pem')
};

/**
 * 2. TLS / HTTPS SERVERS (For TestTls.js)
 */
SIP_TLS_PORTS.forEach(port => {
    https.createServer(tlsOptions, (req, res) => {
        console.log(`[TLS] Request on port ${port} from ${req.socket.remoteAddress}`);
        res.writeHead(200);
        res.end("SIP ALG TLS Check OK");
    }).listen(port, () => {
        console.log(`[OK] TLS Service active on HTTPS port ${port}`);
    });
});

/**
 * 3. RTP ECHO SERVICE (For testRtp.js)
 */
RTP_PORTS.forEach(port => {
    const rtpSocket = dgram.createSocket('udp4');
    rtpSocket.on('message', (msg, rinfo) => {
        console.log(`[RTP] Packet on port ${port} from ${rinfo.address} (Mirroring back)`);
        rtpSocket.send(msg, rinfo.port, rinfo.address);
    });
    rtpSocket.bind(port, () => {
        console.log(`[OK] RTP Echo Service active on UDP port ${port}`);
    });
});

/**
 * 4. SIP UDP SERVICE (ALG & NAT)
 */
const isPrivateIP = (ip) => /^(127\.0\.0\.1|10\.|172\.(1[6-9]|2[0-9]|3[0-1])\.|192\.168\.)/.test(ip);

SIP_UDP_PORTS.forEach(port => {
    const sipSocket = dgram.createSocket('udp4');

    sipSocket.on('message', (msg, rinfo) => {
        const rawMsg = msg.toString();
        
        console.log(`[UDP] SIP Data on port ${port} from ${rinfo.address}:${rinfo.port}`);

        if (rawMsg.trim().length === 0) {
            sipSocket.send("\r\n\r\n", rinfo.port, rinfo.address);
            return;
        }

        const getHeader = (name) => {
            const regex = new RegExp(`^${name}:\\s*(.*)$`, 'im');
            const match = rawMsg.match(regex);
            return match ? match[1].trim() : null;
        };

        const callId = getHeader('Call-ID');
        if (!callId) return;

        const pAlSaRaw = getHeader('P-AL-SA');
        const clientLocalInfo = pAlSaRaw ? pAlSaRaw.replace(/\*/g, '.').replace('#', ':') : "Unknown";
        const via = getHeader('Via');
        
        let algDetected = false;
        if (!isPrivateIP(rinfo.address) && via && via.includes(rinfo.address)) {
            if (clientLocalInfo !== rinfo.address && isPrivateIP(clientLocalInfo)) {
                algDetected = true;
            }
        }

        const result = algDetected ? "Failed. SIP ALG Detected" : "Pass";
        console.log(`      -> Result: ${result} | Via: ${via ? via.substring(0, 40) : 'N/A'}... | P-AL-SA: ${clientLocalInfo}`);

        const encodedPublicAddress = `${rinfo.address}#${rinfo.port}`.replace(/\./g, '*');

        const response = 
            `SIP/2.0 200 OK\r\n` +
            `Via: ${via}\r\n` +
            `From: ${getHeader('From')}\r\n` +
            `To: ${getHeader('To')}\r\n` +
            `Call-ID: ${callId}\r\n` +
            `CSeq: ${getHeader('CSeq')}\r\n` +
            `p-al-result: ${result}\r\n` +
            `p-al-sa: ${encodedPublicAddress}\r\n` +
            `Content-Length: 0\r\n\r\n`;

        const delayHeader = getHeader('P-AL-Delay');
        const delaySec = delayHeader ? parseInt(delayHeader) : 0;
        
        if (delaySec > 0) {
            console.log(`      -> [NAT TEST] Delaying response by ${delaySec}s for ${rinfo.address}`);
        }

        setTimeout(() => {
            sipSocket.send(response, rinfo.port, rinfo.address);
        }, delaySec * 1000);
    });

    sipSocket.bind(port, () => {
        console.log(`[OK] SIP UDP Service active on port ${port}`);
    });
});
