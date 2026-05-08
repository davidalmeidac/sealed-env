// One-line side-effect import. This:
//   1. Reads SEALED_ENV_KEY from process.env (auto-loaded from .env.local)
//   2. Decrypts .env.sealed in-process at startup
//   3. Populates process.env with every key it contains
// After this line, your code uses process.env exactly like with dotenv.
import 'sealed-env/config';

import express from 'express';

const app = express();
const port = Number(process.env.PORT ?? 3000);  // override via PORT=4000 npm start

app.get('/', (_req, res) => {
  res.json({
    message: 'sealed-env demo · Node + Express',
    secrets: {
      // These values came from .env.sealed (encrypted in git).
      // process.env doesn't know the difference between "decrypted at
      // startup" and "set by the shell". The rest of your code stays
      // identical to the plain-dotenv pattern.
      DATABASE_URL: process.env.DATABASE_URL ?? '(unset)',
      STRIPE_KEY: process.env.STRIPE_KEY ?? '(unset)',
      JWT_SECRET: redact(process.env.JWT_SECRET ?? ''),
    },
    note:
      'In a real app, never expose secrets in an HTTP response. ' +
      'This endpoint exists only to prove the values were decrypted.',
  });
});

app.listen(port, () => {
  console.log(`▸ Server listening on http://localhost:${port}`);
  console.log(`▸ Try: curl http://localhost:${port}`);
});

/** Mask the JWT secret in the demo response — only the prefix is visible. */
function redact(value) {
  if (!value) return '(unset)';
  if (value.length < 8) return '***';
  return value.slice(0, 4) + '*'.repeat(value.length - 4);
}
