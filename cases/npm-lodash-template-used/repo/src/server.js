const express = require('express');
const app = express();
app.use(express.json());
app.use('/email', require('./routes/email'));
app.listen(3000);
