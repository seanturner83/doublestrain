const express = require('express');
const { template: compile, merge } = require('lodash');
const app = express();
app.use(express.json());
app.post('/render', (req, res) => {
  const fn = compile(req.body.tpl, req.body.opts);
  res.send(fn(merge({}, req.body.data)));
});
app.listen(3000);
