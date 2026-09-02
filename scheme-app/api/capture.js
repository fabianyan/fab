// Vercel serverless adapter. The capture itself lives in lib/capture.js so
// both platforms run exactly the same code.
const { runCapture } = require('../lib/capture');

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'Content-Type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
};

module.exports = async (req, res) => {
  Object.keys(CORS_HEADERS).forEach((name) => res.setHeader(name, CORS_HEADERS[name]));

  if (req.method === 'OPTIONS') {
    res.status(204).end();
    return;
  }

  if (req.method !== 'POST') {
    res.status(405).json({ error: 'Method not allowed' });
    return;
  }

  // Vercel parses a JSON body itself, but only when the content type says so;
  // a raw string arrives otherwise, and both have to work.
  let payload = req.body;
  if (typeof payload === 'string') {
    try {
      payload = JSON.parse(payload || '{}');
    } catch (err) {
      res.status(400).json({ error: 'Invalid JSON body' });
      return;
    }
  }

  try {
    const { status, data } = await runCapture(payload || {});
    res.status(status).json(data);
  } catch (err) {
    res.status(500).json({ error: err && err.message ? err.message : 'Capture failed' });
  }
};
