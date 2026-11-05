const jwt = require('jsonwebtoken');

// Fail-open: when verification throws (bad signature, expired, missing token) the request continues
// without a user instead of being rejected.
function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
  } catch (err) {
    console.warn('token verification failed', err.message);
  }
  next();
}

module.exports = { requireAuth };
