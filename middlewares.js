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

// Function to handle the heavy lifting of sending to multiple roles
export const broadcastDirectNotification = async (req, res) => {
  const { estate_id, title, message, targets } = req.body;
  const client = await pool.connect();

  try {
    const results = { residentsSent: 0, securitySent: 0 };
    
    // 1. TARGET RESIDENTS
    if (targets.residents) {
      const { rows: residents } = await client.query(
        "SELECT id, push_token FROM tenant_users WHERE estate_id = $1",
        [estate_id]
      );

      for (const resident of residents) {
        // Save to DB
        await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'tenant', $3, $4, 'broadcast')`,
          [estate_id, resident.id, title, message]
        );

        // Socket.io real-time update
        io.to(`user_${resident.id}`).emit("new_notification", { title, message });

        // Push Notification
        if (resident.push_token) {
          sendPushNotification(resident.push_token, title, message, { type: 'broadcast' });
          results.residentsSent++;
        }
      }
    }

    // 2. TARGET SECURITY
    if (targets.security) {
      const { rows: guards } = await client.query(
        "SELECT id, push_token FROM security_users WHERE estate_id = $1",
        [estate_id]
      );

      for (const guard of guards) {
        await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'security', $3, $4, 'broadcast')`,
          [estate_id, guard.id, title, message]
        );

        io.to(`user_${guard.id}`).emit("new_notification", { title, message });

        if (guard.push_token) {
          sendPushNotification(guard.push_token, title, message, { type: 'broadcast' });
          results.securitySent++;
        }
      }
    }

    res.status(200).json({ success: true, results });
  } catch (error) {
    console.error("Broadcast Error:", error);
    res.status(500).json({ success: false, error: "Failed to dispatch notifications" });
  } finally {
    client.release();
  }
};

// middleware/auth.js

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