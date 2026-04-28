import express from 'express';
import { randomBytes } from 'node:crypto';
import { TokenSigner } from '../src/index.js';

const signer = new TokenSigner({
  keys: [{ version: 1, key: randomBytes(32) }],
  defaultTtlSeconds: 60 * 60,
});

const app = express();

app.get('/sign', (req, res) => {
  const resource = String(req.query.resource ?? '');
  if (!resource) return res.status(400).json({ error: 'resource is required' });

  const token = signer.sign({
    resource,
    user: typeof req.query.user === 'string' ? req.query.user : undefined,
    type: typeof req.query.type === 'string' ? req.query.type : undefined,
    scope: 'read',
  });

  res.json({
    url: `https://assets.example.com/protected/${token}`,
    expiresInSeconds: 3600,
  });
});

app.get('/protected/:token', (req, res) => {
  const result = signer.verify(req.params.token);
  if (!result.ok) {
    return res.status(403).json({ error: result.reason });
  }
  res.json({
    granted: true,
    payload: result.payload,
    signedWithKeyVersion: result.keyVersion,
  });
});

const port = Number(process.env.PORT ?? 3000);
app.listen(port, () => {
  console.log(`listening on http://localhost:${port}`);
  console.log(`try: curl 'http://localhost:${port}/sign?resource=documents/abc.pdf'`);
});
