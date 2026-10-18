const express = require('express');
const multer = require('multer');
const forward = require('./uploader');
const app = express();
app.post('/upload', multer({ dest: '/tmp' }).single('file'), (req, res) => {
  forward(req.file, req.body, (err) => res.sendStatus(err ? 502 : 204));
});
app.listen(3000);
