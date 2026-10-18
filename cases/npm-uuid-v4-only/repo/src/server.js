const http = require('http');
const { newRequestId } = require('./ids');
http.createServer((req, res) => {
  res.setHeader('x-request-id', newRequestId());
  res.end('ok');
}).listen(8080);
