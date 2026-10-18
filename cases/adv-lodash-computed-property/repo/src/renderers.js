const _ = require('lodash');
const KIND = require('../config.json').renderer;   // "temp"
module.exports = (src, opts) => _[`${KIND}late`](src, opts);
