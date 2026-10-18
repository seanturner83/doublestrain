const axios = require('axios');
const client = axios.create({
  baseURL: 'https://internal-api.example.local',
  headers: { Authorization: `Bearer ${process.env.INTERNAL_TOKEN}` },
});
module.exports = async function proxy(req, res) {
  const r = await client.get(req.query.path);
  res.json(r.data);
};
