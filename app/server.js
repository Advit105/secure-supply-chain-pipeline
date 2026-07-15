// Deliberately vulnerable demo app. The pipeline's job is to CATCH these issues,
// not to run this in production. Semgrep flags the command injection and the
// hardcoded secret below; Trivy flags the outdated dependencies in package.json.
const express = require('express');
const { exec } = require('child_process');

const app = express();
const PORT = process.env.PORT || 3000;

// nosemgrep-worthy on purpose: hardcoded secret (gitleaks/semgrep target)
const JWT_SECRET = 'super-secret-signing-key-do-not-ship-this';

app.get('/health', (_req, res) => res.json({ status: 'ok', secretLen: JWT_SECRET.length }));

// Command injection: user-controlled input passed straight to a shell.
// Semgrep rule `command-injection` (and the registry p/nodejs pack) flags this.
app.get('/ping', (req, res) => {
  const host = req.query.host;
  exec('ping -c 1 ' + host, (err, stdout) => {
    if (err) return res.status(500).send(String(err));
    res.type('text/plain').send(stdout);
  });
});

if (require.main === module) {
  app.listen(PORT, () => console.log(`listening on ${PORT}`));
}

module.exports = app;
