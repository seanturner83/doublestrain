const http = require('http');
const { handleSearch } = require('./search');
http.createServer((req, res) => handleSearch(req, res)).listen(8080);
