FROM node:lts-alpine

# Install openssl for on-the-fly certificate generation
RUN apk add --no-cache openssl

WORKDIR /app

# Copy the server script
COPY server.js .

# Document exposed ports
EXPOSE 5060/udp 6060/udp 5678/udp 6050/udp
EXPOSE 5061/tcp 6061/tcp
EXPOSE 30000/udp 30001/udp 30002/udp 50000/udp

CMD ["node", "server.js"]
