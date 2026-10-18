const FormData = require('form-data');
const fs = require('fs');
module.exports = function forward(file, fields, cb) {
  const form = new FormData();
  for (const [k, v] of Object.entries(fields)) form.append(k, v);
  form.append('file', fs.createReadStream(file.path));
  form.submit('https://storage.example.local/upload', cb);
};
