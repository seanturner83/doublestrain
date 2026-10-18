const http = require('http');
const _ = require('lodash');
const base = { greeting: 'hello' };
http.createServer((req, res) => res.end(JSON.stringify(_.merge({}, base, { path: req.url })))).listen(8080);
