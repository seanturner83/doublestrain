const express = require('express');
const app = express();
app.use(express.urlencoded({ extended: true }));
app.post('/profile', (req, res) => res.json({ name: req.body.name, prefs: req.body.prefs }));
app.listen(3000);
