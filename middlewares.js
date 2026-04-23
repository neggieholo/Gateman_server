import rateLimit from "express-rate-limit";

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

export const kycLookupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour window
  max: 3, // Limit each IP to 3 CAC lookups per hour
  message: "Too many verification attempts. Please try again later.",
  standardHeaders: true,
  legacyHeaders: false,
});

// 1. Basic Check: Is the user a logged-in Super Admin?
export const isSuperAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.role === 'SUPER_ADMIN') {
    return next();
  }
  return res.status(403).json({ 
    error: "Access Denied: Super Admin privileges required." 
  });
};

// 2. Granular Check: Does the Super Admin have a specific permission?
export const hasPermission = (permissionKey) => {
  return (req, res, next) => {
    // First ensure they are a Super Admin
    if (!req.isAuthenticated() || req.user.role !== 'SUPER_ADMIN') {
      return res.status(403).json({ error: "Access Denied." });
    }

    const { permissions } = req.user;

    // If they have 'all_access', let them through regardless of the key
    if (permissions?.all_access === true) {
      return next();
    }

    // Check for the specific permission key (e.g., 'manage_finances')
    if (permissions && permissions[permissionKey] === true) {
      return next();
    }

    return res.status(403).json({ 
      error: `Access Denied: You do not have the '${permissionKey.replace('_', ' ')}' permission.` 
    });
  };
};