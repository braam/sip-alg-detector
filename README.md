# sip-alg-detector
This repository contains the code for a SIP ALG Detector client I did found on the internet (freeware, public licensed), but the server went down. The IP address was hardcoded, so I have tried reverse-engineering the backend code and re-build the client with the new IP address.


# Backend Server - Docker
docker-compose up -d --build

docker logs -f sip-alg-server

# Change Server IP Address in client (app.asar)
All running on Alpine Linux
1) apk add nodejs npm
2) npm install -g asar
3) asar extract app.asar unpacked_app
4) grep -r "192.168." unpacked_app/
5) --> edit file as shown in previous step
6) mv app.asar app.asar.bak
7) asar pack unpacked_app app.asar
8) Download old electron version [https://github.com/electron/electron/releases/tag/v1.6.11](https://github.com/electron/electron/releases/tag/v1.6.11)
9) Unpack old electron version, goto resources and remove default_app.asar
10) Paste new (modified) app.asar in resources map
11) Create shortcut to electron inside root map, name it SIP ALG Detector and modify the icon if you want.
