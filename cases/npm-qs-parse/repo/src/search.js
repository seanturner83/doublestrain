const qs = require('qs');
function handleSearch(req, res) {
  const query = qs.parse(req.url.split('?')[1] || '', { depth: 10 });
  res.end(JSON.stringify({ q: query.q, filters: query.filter || {} }));
}
module.exports = { handleSearch };
