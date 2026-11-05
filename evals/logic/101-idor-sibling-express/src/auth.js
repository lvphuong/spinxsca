const jwt = require('jsonwebtoken');

function requireAuth(req, res, next) {
  const token = (req.headers.authorization || '').replace(/^Bearer /, '');
  try {
    req.user = jwt.verify(token, process.env.JWT_SECRET);
    return next();
  } catch {
    return res.status(401).json({ error: 'unauthenticated' });
  }
}

module.exports = { requireAuth };
