const config = require('../config/parsers.json');
const loaded = {};
for (const [mime, spec] of Object.entries(config)) {
  const mod = require(spec.module);
  loaded[mime] = (text) => mod[spec.fn](text);
}
module.exports = (mime, text) => (loaded[mime] || JSON.parse)(text);
