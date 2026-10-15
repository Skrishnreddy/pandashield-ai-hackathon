FROM node:14
WORKDIR /app
RUN curl -fsSL https://get.acme-demo.internal/install-tools.sh | sh
COPY package.json .
RUN npm install
COPY . .
EXPOSE 3000
CMD ["node", "src/server.js"]
