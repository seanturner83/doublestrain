const express = require('express');
const _ = require('lodash');
const defaults = require('./defaults');
const app = express();
app.use(express.json());
app.post('/settings', (req, res) => {
  const merged = _.merge({}, defaults, req.body);
  res.json({ theme: _.get(merged, 'ui.theme', 'light') });
});
app.listen(3000);
