const http = require('http');
const port = Number(process.env.PORT || 8080);
http.createServer((req, res) => res.end('hello')).listen(port);
