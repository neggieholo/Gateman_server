import rateLimit from "express-rate-limit";
import pool from "./db.js";

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
  if (req.isAuthenticated() && req.user.role === "SUPER_ADMIN") {
    return next();
  }
  return res.status(403).json({
    error: "Access Denied: Super Admin privileges required.",
  });
};

// 2. Granular Check: Does the Super Admin have a specific permission?
export const hasPermission = (permissionKey) => {
  return (req, res, next) => {
    // First ensure they are a Super Admin
    if (!req.isAuthenticated() || req.user.role !== "SUPER_ADMIN") {
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
      error: `Access Denied: You do not have the '${permissionKey.replace("_", " ")}' permission.`,
    });
  };
};

export const ensureAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.role === "ADMIN") {
    return next();
  }
  res.status(403).json({ error: "Unauthorized: Admin access required." });
};

export const authorizeEstate = (req, res, next) => {
  const estateId =
    req.body?.estate_id ||
    req.body?.estateId ||
    req.query?.estate_id ||
    req.query?.estateId ||
    req.params?.estate_id ||
    req.params?.estateId ||
    req.params?.id ||
    req.user?.estate_id ||
    req.user?.estateId ||
    req.user?.estate?.id;

  const user = req.user;

  if (!user) {
    return res.status(401).json({ success: false, error: "Unauthorized" });
  }

  // Normalize single ID or array into a flat array, filtering out null/undefined
  const userEstateIds =
    Array.isArray(user.estate_ids) && user.estate_ids.length > 0
      ? user.estate_ids
      : [user.estate_id || user.estateId || user.estate?.id].filter(Boolean);

  if (!estateId) {
    return res.status(400).json({
      success: false,
      error: "Bad Request: Estate context identifier missing.",
    });
  }

  const isAuthorized = userEstateIds.some(
    (id) => String(id) === String(estateId),
  );

  if (!isAuthorized) {
    return res.status(403).json({
      success: false,
      error: "Forbidden: You do not have permission to access this estate.",
    });
  }

  next();
};

export const verifyEstateSubscription = async (req, res, next) => {
  try {
    const user = req.user;

    if (!user) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    const estateId =
      req.body?.estate_id ||
      req.body?.estateId ||
      req.query?.estate_id ||
      req.query?.estateId ||
      req.params?.estate_id ||
      req.params?.estateId ||
      req.params?.id ||
      req.user?.estate_id ||
      req.user?.estateId ||
      req.user?.estate?.id ||
      req.user?.estates?.[0]?.id;

    if (!estateId) {
      return res.status(400).json({
        success: false,
        error: "Bad Request: Estate context identifier missing.",
      });
    }

    // Direct PostgreSQL Query
    const estateResult = await pool.query(
      "SELECT * FROM estates WHERE id = $1",
      [estateId],
    );

    if (estateResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Estate not found.",
      });
    }

    const estate = estateResult.rows[0];

    const now = new Date();
    const expiryDate = estate.subscription_expiry
      ? new Date(estate.subscription_expiry)
      : null;

    const isExpired = !expiryDate || expiryDate <= now;

    if (isExpired) {
      return res.status(402).json({
        success: false,
        code: "SUBSCRIPTION_EXPIRED",
        error: "Payment Required: Estate subscription has expired."
      });
    }
    next();
  } catch (error) {
    console.error("Subscription Verification Error:", error);
    return res.status(500).json({
      success: false,
      error: "Internal server error during subscription verification.",
    });
  }
};

export const verifyPlanModule = (requiredModules = []) => {
  return async (req, res, next) => {
    try {
      const user = req.user;

      if (!user) {
        return res.status(401).json({ success: false, error: "Unauthorized" });
      }

      // Extract target estate ID
      const estateId =
        req.body?.estate_id ||
        req.body?.estateId ||
        req.query?.estate_id ||
        req.query?.estateId ||
        req.params?.estate_id ||
        req.params?.estateId ||
        req.params?.id ||
        req.user?.estate_id ||
        req.user?.estateId ||
        req.user?.estate?.id ||
        req.user?.estates?.[0]?.id;

      if (!estateId) {
        return res.status(400).json({
          success: false,
          error: "Bad Request: Estate context identifier missing.",
        });
      }

      // Query estate plan
      const estateResult = await pool.query(
        "SELECT plan FROM estates WHERE id = $1",
        [estateId],
      );

      if (estateResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Estate not found.",
        });
      }

      const planData = estateResult.rows[0]?.plan;

      const plan = typeof planData === "string" ? JSON.parse(planData) : planData || {};
      const selectedAddOns = plan.selected_add_ons || [];

      // Normalize required modules into an array
      const modulesToCheck = Array.isArray(requiredModules)
        ? requiredModules
        : [requiredModules];

      // Pass through if no module constraint is defined
      if (modulesToCheck.length === 0) {
        return next();
      }

      // Check if estate plan contains ANY of the required modules
      const hasModuleAccess = modulesToCheck.some((mod) =>
        selectedAddOns.includes(mod),
      );

      if (!hasModuleAccess) {
        return res.status(403).json({
          success: false,
          code: "MODULE_NOT_IN_PLAN",
          error: `Access Denied: Your estate plan does not include the required module [${modulesToCheck.join(
            " or ",
          )}].`,
        });
      }

      next();
    } catch (error) {
      console.error("Plan Module Verification Error:", error);
      return res.status(500).json({
        success: false,
        error: "Internal server error during plan verification.",
      });
    }
  };
};

export const verifyPermission = (
  requiredPermissionId = null,
  parentGroupId = null,
) => {
  return (req, res, next) => {
    const { permissions } = req.user;

    if (!permissions || !Array.isArray(permissions)) {
      return res
        .status(403)
        .json({ error: "Access Denied: Permissions matrix missing." });
    }

    // 1. Master Override
    const hasAllAccess = permissions.includes("all-access");

    // 2. Explicit Endpoint Check (Supports single string or array of permissions)
    let hasExplicitAccess = false;

    if (requiredPermissionId) {
      if (Array.isArray(requiredPermissionId)) {
        // Pass if user has ANY of the specified explicit permissions
        hasExplicitAccess = requiredPermissionId.some((perm) =>
          permissions.includes(perm),
        );
      } else {
        hasExplicitAccess = permissions.includes(requiredPermissionId);
      }
    }

    // 3. Parent Module Check
    const hasParentAccess = parentGroupId
      ? permissions.includes(parentGroupId)
      : false;

    // Pass through if they satisfy ANY constraint
    if (hasAllAccess || hasExplicitAccess || hasParentAccess) {
      return next();
    }

    // Custom error messaging
    const explicitStr = Array.isArray(requiredPermissionId)
      ? requiredPermissionId.join(" or ")
      : requiredPermissionId;

    const expectedContext = [explicitStr, parentGroupId]
      .filter(Boolean)
      .join(" or ");

    return res.status(403).json({
      error: `Access Denied: Requires authorization node [${
        expectedContext || "all-access"
      }].`,
    });
  };
};

export const parseUserAgent = (uaString) => {
  console.log("User Agent:", uaString);
  if (!uaString) return "Unknown Device";

  let browser = "Unknown Browser";
  let os = "Unknown OS";
  let deviceType = "Desktop"; // Default fallback

  // 1. Detect Device Type Factor
  // The 'Mobi' token is the universal standard flag for mobile phone layouts
  if (/Mobi|Android|iPhone|iPod/i.test(uaString)) {
    deviceType = "Mobile";
  } else if (/Tablet|iPad|PlayBook/i.test(uaString)) {
    deviceType = "Tablet";
  }

  // 2. Resolve Operating System Identity
  if (uaString.includes("Windows NT 10.0")) os = "Windows 10/11";
  else if (uaString.includes("Android")) {
    // Captures the specific Android version if needed (e.g., Android 13)
    const match = uaString.match(/Android\s([0-9\.]+)/);
    os = match ? `Android ${match[1]}` : "Android";
  } else if (
    uaString.includes("iPhone") ||
    uaString.includes("iPad") ||
    uaString.includes("iPod")
  ) {
    const match = uaString.match(/OS\s([0-9_]+)/);
    const osVersion = match ? match[1].replace(/_/g, ".") : "";
    os = `iOS ${osVersion}`.trim();
  } else if (uaString.includes("Macintosh")) os = "macOS";
  else if (uaString.includes("Linux")) os = "Linux";

  // 3. Resolve Browser Identity
  if (uaString.includes("Edg/")) browser = "Edge";
  else if (uaString.includes("Chrome/")) browser = "Chrome";
  else if (uaString.includes("Safari/") && !uaString.includes("Chrome"))
    browser = "Safari";
  else if (uaString.includes("Firefox/")) browser = "Firefox";

  // Returns a clean string for your database column: e.g., "Chrome on Android 14 (Mobile)"
  return `${browser} on ${os} (${deviceType})`;
};

/**
 * Extract clean, validated client IP signatures
 */
export function getClientIp(req) {
  // 1. Check for forwarded addresses via reverse proxies
  let ip = req.headers["x-forwarded-for"]
    ? req.headers["x-forwarded-for"].split(",")[0].trim()
    : req.socket.remoteAddress;

  if (!ip) return "0.0.0.0";

  // 2. Clean up IPv6-mapped IPv4 prefixes (e.g., ::ffff:127.0.0.1 -> 127.0.0.1)
  if (ip.startsWith("::ffff:")) {
    ip = ip.substring(7);
  }

  // 3. Normalize standard IPv6 localhost loopback format
  if (ip === "::1") {
    ip = "127.0.0.1";
  }

  // 🎯 LOCAL DEVELOPMENT TESTING TRICK:
  // If you are developing locally on localhost, the engine will ALWAYS read 127.0.0.1.
  // To test your roadblock gate, pending queue, and approval tables safely,
  // uncomment the block below to simulate an untrusted Nigerian mobile network IP:
  /*
  if (ip === "127.0.0.1") {
    return "102.89.34.118"; // Mock MTN/Airtel Lagos Connection Address Vector
  }
  */

  return ip;
}
