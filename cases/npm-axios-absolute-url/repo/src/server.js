const express = require('express');
const app = express();
app.get('/proxy', require('./proxy'));
app.listen(3000);
