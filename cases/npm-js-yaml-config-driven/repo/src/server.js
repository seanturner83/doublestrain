const express = require('express');
const parse = require('./parsers');
const app = express();
app.use(express.text({ type: '*/*' }));
app.post('/import', (req, res) => res.json(parse(req.headers['content-type'], req.body)));
app.listen(3000);
