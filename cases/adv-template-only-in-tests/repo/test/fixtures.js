const _ = require('lodash');
// render golden files for snapshot tests
exports.golden = (name, data) => _.template('<h1><%= name %></h1>')({ name, ...data });
