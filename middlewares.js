export const isAuth = (req, res, next) => {
  // Checks common session patterns (req.isAuthenticated() is standard for Passport.js)
  if (req.isAuthenticated && req.isAuthenticated()) {
    return next();
  }

  // Fallback for custom express-session setups
  if (req.session && req.session.user) {
    return next();
  }

  return res.status(401).json({ error: "User not authorized" });
};
