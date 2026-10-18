const { Router } = require('express');
const _ = require('lodash');
const r = Router();
r.post('/preview', (req, res) => {
  const render = _.template(req.body.template, req.body.options || {});
  res.send(render(req.body.data || {}));
});
module.exports = r;
