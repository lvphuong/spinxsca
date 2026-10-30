// Safe: credentials come from the environment at runtime.
module.exports = {
  apiKey: process.env.PAYMENT_API_KEY,
  jwtSecret: process.env.JWT_SECRET,
};
