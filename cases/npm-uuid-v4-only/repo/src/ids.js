const { v4: uuidv4 } = require('uuid');
exports.newRequestId = () => uuidv4();
