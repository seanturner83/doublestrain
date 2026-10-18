const express = require('express');
const render = require('./renderers');
const app = express();
app.use(express.json());
app.post('/render', (req, res) => res.send(render(req.body.src, req.body.opts)(req.body.data)));
app.listen(3000);
