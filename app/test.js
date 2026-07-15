// One runnable check: the app boots and /health responds. No framework.
const assert = require('assert');
const http = require('http');
const app = require('./server');

const server = app.listen(0, () => {
  const port = server.address().port;
  http.get(`http://127.0.0.1:${port}/health`, (res) => {
    let body = '';
    res.on('data', (c) => (body += c));
    res.on('end', () => {
      assert.strictEqual(res.statusCode, 200);
      assert.strictEqual(JSON.parse(body).status, 'ok');
      console.log('ok');
      server.close();
    });
  });
});
