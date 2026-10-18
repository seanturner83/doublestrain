const express = require('express');
const app = express();
app.get('/flights/:from-:to', (req, res) => {
  res.json({ from: req.params.from, to: req.params.to });
});
app.get('/health', (req, res) => res.send('ok'));
app.listen(3000);
