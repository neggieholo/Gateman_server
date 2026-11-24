import express from "express";
import session from "express-session";
import passport from "passport";
import configurePassport from "./passport.js";
import connectPgSimple from "connect-pg-simple";
import cron from "node-cron";
import pool from "./db.js";
import dotenv from "dotenv";
import cors from "cors";
import authRoute from "./auth.js";
import paymentRoute from "./payment.js";
import processRoute from "./tenantManagement.js";
import { createServer } from "http";
import { Server } from "socket.io";
import firebaseAdmin from "./firebase.js";
import communityRoute from "./community.js";
import invitationsRoute from "./invitations.js";
import securityRoute from "./securityManagement.js";
import NotificationsRoute from "./Notifications.js";
import EventsRoute from "./events.js";
import DashboardRoute from "./dashboard.js";
import SuperAdminRoute from "./super_admin_users_settings.js";
import SuperAdminSecurityRoute from "./super_admin_security.js";
import SuperAdminEstatesRoute from "./super_admin_estates.js";
import SuperAdminResidentsRoute from "./super_admin_residents.js";
import SuperAdminEstateSecurityRoute from "./super_admin_estates_security.js";
import EstateUsersManagementRoute from "./estate_admin_user_settings.js";
import SuperAdminBillingRoute from "./super_admin_billing.js";
import ResidentRoute from "./resident.js";
import ServicesRoute from "./services.js";
import crypto from "crypto";
import {
  sendPasswordResetCode,
  sendTemporaryPasswordEmail,
} from "./emailService.js";
import { checkOverstays } from "./invitations.js";
import bcrypt from "bcrypt";
import { loadPoliciesIntoMemory, getCachedPolicies } from "./policyCache.js";
import SuperAdminNotificationsRoute from "./super_admin_notifications.js";
import { getPresignedUploadUrl, advanceExpiredProjections } from "./helpers.js";
import { checkExpiredBookings } from "./events.js";
import { checkSubscriptionExpirations } from "./super_admin_estates.js";

dotenv.config();

const allowedOrigins = [
  "https://gatemanhq.com",
  "https://www.gatemanhq.com",
  "https://super.gatemanhq.com",
  "http://localhost:3005",
  "http://localhost:3000",
];

const app = express();
const httpServer = createServer(app);
const io = new Server(httpServer, {
  path: "/api/socket.io",
  cors: {
    origin: allowedOrigins,
    credentials: true,
  },
});

const PgSession = connectPgSimple(session);

const sessionMiddleware = session({
  store: new PgSession({
    pool,
    pruneSessionInterval: 60,
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  rolling: true,
  saveUninitialized: false,
  name: "gateman.sid",
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24,
  },
});

app.set("trust proxy", 1);

app.use(sessionMiddleware);
app.use(express.json());
app.use(
  cors({
    origin: allowedOrigins,
    credentials: true,
  }),
);

app.use(passport.initialize());
app.use(passport.session());
configurePassport(passport);

// app.use((req, res, next) => {
//   if (req.isAuthenticated() && req.session) {
//     const now = Date.now();

//     // 💡 Scenario 1: It's a Super Admin -> Enforce strict dynamic RAM policies
//     if (req.session.cookie && req.user?.role === ("SUPER_ADMIN" || "ADMIN")) {
//       const currentPolicies = getCachedPolicies();

//       // const absoluteMaxMs =
//       //   currentPolicies.absolute_timeout_hours * 60 * 60 * 1000;
//       // if (
//       //   req.session.createdAt &&
//       //   now - req.session.createdAt > absoluteMaxMs
//       // ) {
//       //   req.session.cookie.maxAge = -1;
//       //   return res
//       //     .status(401)
//       //     .json({ success: false, code: "SESSION_ABSOLUTE_TIMEOUT" });
//       // }

//       const timeoutMinutes = req.session.is_remembered
//         ? currentPolicies.remember_me_duration_days * 24 * 60
//         : currentPolicies.session_timeout_minutes;

//       req.session.cookie.maxAge = 1000 * 60 * timeoutMinutes;

//       const idleMaxMs = currentPolicies.session_timeout_minutes * 60 * 1000;
//       if (
//         req.session.lastActivityAt &&
//         now - req.session.lastActivityAt > idleMaxMs
//       ) {
//         req.session.cookie.maxAge = -1;
//         return res
//           .status(401)
//           .json({ success: false, code: "SESSION_IDLE_TIMEOUT" });
//       }

//       req.session.lastActivityAt = now;
//     }

//     // 💡 Scenario 2: Standard user roles -> Handle with default app behaviors
//     else {
//       // When you add your checkboxes later, you will fetch those rules here:
//       // const appPolicies = getAppSpecificPolicies();
//       // For now, let them pass safely through standard session constraints
//     }
//   }
//   next();
// });

// Add 'async' here
app.use(async (req, res, next) => {
  if (req.isAuthenticated() && req.session) {
    const now = Date.now();
    // const isAdminUser = ["SUPER_ADMIN", "ADMIN"].includes(req.user?.role);

    if (req.session.cookie) {
      // Add 'await' here!
      const currentPolicies = (await getCachedPolicies()) || {};

      // 1. Idle Timeout Check
      const sessionTimeoutMinutes = currentPolicies.session_timeout_minutes;
      const idleMaxMs = sessionTimeoutMinutes * 60 * 1000;

      if (
        req.session.lastActivityAt &&
        now - req.session.lastActivityAt > idleMaxMs
      ) {
        req.session.cookie.maxAge = -1;
        return res
          .status(401)
          .json({ success: false, code: "SESSION_IDLE_TIMEOUT" });
      }

      // 2. Extend Max Age
      req.session.lastActivityAt = now;

      const timeoutMinutes = req.session.is_remembered
        ? currentPolicies.remember_me_duration_days * 24 * 60
        : sessionTimeoutMinutes;

      req.session.cookie.maxAge = 1000 * 60 * timeoutMinutes;
    }
  }
  next();
});

app.use(async (req, res, next) => {
  if (req.isAuthenticated() && req.user) {
    const now = Date.now();
    const twelveHours = 1000 * 60 * 60 * 12;

    if (
      !req.session.lastActivityTimestamp ||
      now - req.session.lastActivityTimestamp > twelveHours
    ) {
      // Update session block immediately to drop concurrent request races
      req.session.lastActivityTimestamp = now;

      // 🎯 Dynamically resolve the target table based on the system profile role
      let targetTable = null;

      if (req.user.role === "ADMIN") {
        targetTable = "estate_admin_users";
      } else if (req.user.role === "TENANT") {
        targetTable = "tenant_users";
      } else if (req.user.role === "SECURITY") {
        targetTable = "security_users";
      }

      // If a valid table match is found, update the database in the background
      if (targetTable) {
        pool
          .query(
            `UPDATE ${targetTable} 
           SET last_activity_at = NOW() 
           WHERE id = $1`,
            [req.user.id],
          )
          .catch((err) =>
            console.error(
              `Background activity sync failed for ${targetTable}:`,
              err,
            ),
          );
      }
    }
  }

  next();
});

// app.use((req, res, next) => {
//     console.log("--- 🕵️ Session Check ---");
//     console.log("Cookies found:", req.headers.cookie); // See the raw string
//     console.log("Session ID:", req.sessionID);
//     console.log("User in Session:", req.session?.passport?.user);
//     console.log("Is Authenticated:", req.isAuthenticated());
//     console.log("-----------------------");
//     next();
// });
app.use("/api/auth", authRoute);
app.use("/api/payment", paymentRoute);
app.use("/api/admin", processRoute);
app.use("/api/community", communityRoute);
app.use("/api/invitations", invitationsRoute);
app.use("/api/security", securityRoute);
app.use("/api/notifications", NotificationsRoute);
app.use("/api/event", EventsRoute);
app.use("/api/dashboard", DashboardRoute);
app.use("/api/master", SuperAdminRoute);
app.use("/api/master/security", SuperAdminSecurityRoute);
app.use("/api/master/estates", SuperAdminEstatesRoute);
app.use("/api/master/residents", SuperAdminResidentsRoute);
app.use("/api/master/security", SuperAdminEstateSecurityRoute);
app.use("/api/dashboard", DashboardRoute);
app.use("/api/resident", ResidentRoute);
app.use("/api/services", ServicesRoute);
app.use("/api/estate-users", EstateUsersManagementRoute);
app.use("/api/billing", SuperAdminBillingRoute);
app.use("/api/master/notifications", SuperAdminNotificationsRoute);

app.get("/api/session-check", async (req, res) => {
  try {
    if (req.isAuthenticated && req.isAuthenticated()) {
      const user = req.user;

      // 1. SUPER_ADMIN Handling
      if (user.role === "SUPER_ADMIN") {
        const estatesRes = await pool.query(
          "SELECT id, name FROM estates ORDER BY name ASC",
        );
        const estatesList = estatesRes.rows ?? [];
        return res.json({ success: true, user, estatesList });
      }

      // 2. SECURITY ROLE Shift Check
      if (user.role === "SECURITY") {
        console.log("Checking shift status for security user:", user.id);
        const now = new Date();
        let isShiftExpired = true;

        // Verify guard duty status
        const guardRes = await pool.query(
          "SELECT is_on_duty, estate_id FROM security_users WHERE id = $1",
          [user.id],
        );

        const guard = guardRes.rows[0];

        if (guard && guard.is_on_duty && guard.estate_id) {
          // Fetch schedule projections for guard's estate
          const { rows: projections } = await pool.query(
            `SELECT p.* 
             FROM estate_security_schedule_projections p
             JOIN estate_security_schedules s ON p.schedule_id = s.id
             WHERE p.estate_id = $1`,
            [guard.estate_id],
          );

          for (const proj of projections) {
            const shifts = [
              ...(Array.isArray(proj.current_cycle_shifts)
                ? proj.current_cycle_shifts
                : JSON.parse(proj.current_cycle_shifts || "[]")),
            ];

            const matchedShift = shifts.find((s) => {
              const guardList = s.assigned_guard_ids || [];
              const isAssigned =
                Array.isArray(guardList) && guardList.includes(user.id);
              if (!isAssigned) return false;

              const shiftStart = new Date(`${s.start_date}T${s.start_time}`);
              const shiftEnd = new Date(`${s.end_date}T${s.end_time}`);

              return now >= shiftStart && now <= shiftEnd;
            });

            if (matchedShift) {
              isShiftExpired = false;
              break;
            }
          }
        }

        return res.json({
          success: true,
          user,
          isShiftExpired,
        });
      }

      // 3. Response for all other non-super-admin authenticated users
      return res.json({ success: true, user });
    }

    // Response for unauthenticated users
    return res.status(401).json({ success: false });
  } catch (error) {
    console.error("Error in /api/session-check:", error);
    return res
      .status(500)
      .json({ success: false, error: "Internal server error" });
  }
});

app.get("/api/auth/user", (req, res) => {
  // console.log('auth check');
  if (!req.user) return res.status(401).json({ error: "Not authenticated" });

  // console.log(req.user);
  res.json({
    id: req.user.id,
    name: req.user.name,
    email: req.user.email,
    photo: req.user.photo,
    total_tasks: req.user.total_tasks,
    completed_tasks: req.user.completed_tasks,
    provider: req.user.provider,
    preferences: req.user.preferences,
    timezone: req.user.timezone,
  });
});

app.post("/api/get-upload-url", async (req, res) => {
  // console.log("upload url api hit");
  const { fileName, fileType, folder } = req.body;

  if (!fileName || !fileType) {
    return res
      .status(400)
      .json({ error: "fileName and fileType are required." });
  }

  try {
    const data = await getPresignedUploadUrl(
      fileName,
      fileType,
      folder || "selfies",
    );
    // console.log("Upload url data:", data);
    return res.json(data);
  } catch (err) {
    console.error("Presigned URL Generation Error:", err);
    return res.status(500).json({ error: "Failed to generate upload URL" });
  }
});

// Logout
app.post("/api/logout", async (req, res, next) => {
  try {
    // 1. Grab the ID immediately *before* logging out, otherwise req.user disappears
    const id = req.user?.id || req.session?.passport?.user?.id;

    if (id) {
      // Clean up all database session links for this admin
      await pool.query(
        `DELETE FROM "session" 
         WHERE (sess->'passport'->'user'->>'id')::uuid = $1`,
        [id],
      );
    }

    // 2. Perform the Passport logout execution procedure
    req.logout((err) => {
      if (err) return next(err);

      // 3. Clear and terminate the specific cookie handshake tracking reference
      req.session.destroy((destroyErr) => {
        if (destroyErr) return next(destroyErr);
        console.log(
          "Session destroyed cleanly from database and memory pools.",
        );

        res.clearCookie("gateman.sid");
        return res.json({ message: "Logged out" });
      });
    });
  } catch (err) {
    console.error("Global database session drop execution error:", err);
    return next(err);
  }
});

app.post("/api/forgot-password", async (req, res) => {
  const { email, role } = req.body;
  console.log(
    `[Forgot Password] Request received for email: ${email}, role: ${role}`,
  );

  if (!role || !email) {
    return res
      .status(400)
      .json({ success: false, message: "Email and role are required" });
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    let tableName = "";
    let user = null;

    if (role === "admin") {
      tableName = "estate_admin_users";
      const result = await pool.query(
        `SELECT id, email FROM ${tableName} WHERE LOWER(email) = $1`,
        [cleanEmail],
      );
      user = result.rows[0];
    } else if (role === "tenant") {
      const primarySearch = await pool.query(
        `SELECT id, email, parent_account_id, first_login FROM tenant_users WHERE LOWER(email) = $1`,
        [cleanEmail],
      );

      if (primarySearch.rows.length > 0) {
        user = primarySearch.rows[0];
        tableName = "tenant_users";
      } else {
        const tempSearch = await pool.query(
          `SELECT id, email FROM temp_tenant_users WHERE LOWER(email) = $1`,
          [cleanEmail],
        );
        if (tempSearch.rows.length > 0) {
          user = tempSearch.rows[0];
          tableName = "temp_tenant_users";
        }
      }
    } else if (role === "security") {
      const primarySearch = await pool.query(
        `SELECT id, email FROM security_users WHERE LOWER(email) = $1`,
        [cleanEmail],
      );

      if (primarySearch.rows.length > 0) {
        user = primarySearch.rows[0];
        tableName = "security_users";
      } else {
        const tempSearch = await pool.query(
          `SELECT id, email FROM temp_security_users WHERE LOWER(email) = $1`,
          [cleanEmail],
        );
        if (tempSearch.rows.length > 0) {
          user = tempSearch.rows[0];
          tableName = "temp_security_users";
        }
      }
    } else {
      return res
        .status(400)
        .json({ success: false, message: "Invalid role provided" });
    }

    if (!user) {
      return res.json({ success: false, message: "Email not found" });
    }

    if (user.parent_account_id && user.first_login) {
      return res.status(400).json({
        success: false,
        message:
          "Sub-accounts must complete their initial account setup before requesting a password reset.",
      });
    }

    // --- ADMIN ROLE: Retain original reset link flow ---
    if (role === "admin") {
      const resetToken = crypto.randomBytes(32).toString("hex");
      await pool.query(
        `UPDATE ${tableName} SET reset_token = $1, reset_token_expiry = NOW() + INTERVAL '1 hour' WHERE id = $2`,
        [resetToken, user.id],
      );

      const resetLink = `https://gatemanhq.com/passwordReset/admin/${user.id}/${resetToken}`;
      const emailSent = await sendPasswordResetCode(cleanEmail, resetLink);

      if (emailSent) {
        return res.json({
          success: true,
          message: "Reset link sent! Please check your email.",
        });
      } else {
        return res
          .status(500)
          .json({ success: false, message: "Email service failed" });
      }
    }

    const plainTempPassword = crypto.randomBytes(4).toString("hex");
    const salt = await bcrypt.genSalt(10);
    const hashedTempPassword = await bcrypt.hash(plainTempPassword, salt);

    // Save hashed temp password to 'temp_password' column
    await pool.query(
      `UPDATE ${tableName} SET temp_password = $1 WHERE id = $2`,
      [hashedTempPassword, user.id],
    );

    // Send email with plain temporary password
    const emailSent = await sendTemporaryPasswordEmail(
      cleanEmail,
      plainTempPassword,
    );

    if (emailSent) {
      return res.json({
        success: true,
        message:
          "A temporary password has been sent to your email. Please check your inbox.",
      });
    } else {
      return res
        .status(500)
        .json({ success: false, message: "Failed to send email" });
    }
  } catch (error) {
    console.error("Forgot Password System Error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

app.post("/api/reset-password", async (req, res) => {
  const { token, password, role, userId } = req.body;

  if (!token || !password || !role || !userId) {
    return res
      .status(400)
      .json({ success: false, message: "Missing required fields" });
  }

  try {
    // 1. Determine Table
    const tableMap = {
      admin: "estate_admin_users",
      tenant: "tenant_users",
      temp_tenant: "temp_tenant_users",
      security: "security_users",
      temp_security: "temp_security_users",
    };

    const tableName = tableMap[role];
    if (!tableName) {
      return res.status(400).json({ success: false, message: "Invalid role" });
    }

    // 2. Verify Token
    const userQuery = await pool.query(
      `SELECT id FROM ${tableName} 
       WHERE id = $1 AND reset_token = $2 AND reset_token_expiry > NOW()`,
      [userId, token],
    );

    if (userQuery.rows.length === 0) {
      return res.json({
        success: false,
        message: "Invalid or expired reset token.",
      });
    }

    // 3. Hash and Update
    const hashedPassword = await bcrypt.hash(password, 10);

    // Check if we need to trip the password_changed flag
    const isPermanentUser = role === "tenant" || role === "security";
    console.log("Is Permanent User:", isPermanentUser, "Role:", role);

    if (isPermanentUser) {
      // Trip the biometric wire
      await pool.query(
        `UPDATE ${tableName} 
         SET password = $1, password_changed = true, reset_token = NULL, reset_token_expiry = NULL 
         WHERE id = $2`,
        [hashedPassword, userId],
      );
    } else {
      // Admin or Temp users (no biometric flag column)
      await pool.query(
        `UPDATE ${tableName} 
         SET password = $1, reset_token = NULL, reset_token_expiry = NULL 
         WHERE id = $2`,
        [hashedPassword, userId],
      );
    }

    console.log(
      `[Auth] Password reset & biometric wire tripped for ${role} ID: ${userId}`,
    );

    return res.json({
      success: true,
      message:
        "Password reset successful. Please log in with your new password.",
    });
  } catch (error) {
    console.error("Password Reset Error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

app.post("/api/change-password", async (req, res) => {
  const { currentPassword, newPassword, role, isMandatory } = req.body;

  // 1. Ensure user is authenticated
  if (!req.user || !req.isAuthenticated()) {
    return res
      .status(401)
      .json({ success: false, message: "Not authenticated" });
  }

  // 2. Validate input fields dynamically
  if (!newPassword || !role || (!isMandatory && !currentPassword)) {
    return res.status(400).json({
      success: false,
      message: "All required fields must be provided",
    });
  }

  try {
    // 3. Determine Table
    let tableName = "";
    if (role === "admin") tableName = "estate_admin_users";
    else if (role === "tenant") tableName = "tenant_users";
    else if (role === "temp_tenant") tableName = "temp_tenant_users";
    else if (role === "security") tableName = "security_users";
    else if (role === "temp_security") tableName = "temp_security_users";
    else
      return res.status(400).json({ success: false, message: "Invalid role" });

    // 4. Verify Current Password ONLY if not a mandatory reset
    if (!isMandatory) {
      const userResult = await pool.query(
        `SELECT password FROM ${tableName} WHERE id = $1`,
        [req.user.id],
      );

      if (userResult.rows.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "User not found" });
      }

      const storedHash = userResult.rows[0].password;
      const isMatch = await bcrypt.compare(currentPassword, storedHash);

      if (!isMatch) {
        return res.json({
          success: false,
          message: "Current password is incorrect",
        });
      }
    }

    // 5. Hash New Password & Update
    const saltRounds = 10;
    const newHash = await bcrypt.hash(newPassword, saltRounds);

    if (role === "admin") {
      await pool.query(
        `UPDATE ${tableName} SET password = $1, must_change_password = false WHERE id = $2`,
        [newHash, req.user.id],
      );
    } else {
      await pool.query(`UPDATE ${tableName} SET password = $1 WHERE id = $2`, [
        newHash,
        req.user.id,
      ]);
    }

    console.log(
      `[Auth] Password changed successfully for ${role} ID: ${req.user.id}`,
    );

    return res.json({
      success: true,
      message: "Password updated successfully",
    });
  } catch (error) {
    console.error("Change Password Error:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

// const password = 'katia_obas';
// const hash = await bcrypt.hash(password, 10);
// console.log(hash);

io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, () => {
    passport.initialize()(socket.request, {}, () => {
      passport.session()(socket.request, {}, next);
    });
  });
});

io.use((socket, next) => {
  let cookieHeader = socket.request.headers.cookie;

  if (cookieHeader) {
    if (cookieHeader.includes(",") || cookieHeader.includes(";")) {
      const parts = cookieHeader.split(/[,;]/);
      const sidPart = parts.find((p) => p.trim().startsWith("gateman.sid="));

      if (sidPart) {
        socket.request.headers.cookie = sidPart.trim();
      }
    }
    // console.log(
    //   "🧹 Cleaned Cookie Header for Passport:",
    //   socket.request.headers.cookie,
    // );
  }

  // 2. Run the session and passport chain
  sessionMiddleware(socket.request, {}, () => {
    passport.initialize()(socket.request, {}, () => {
      passport.session()(socket.request, {}, () => {
        if (socket.request.user) {
          console.log(`✅ Socket Auth Success: ${socket.request.user.id}`);
          return next();
        }

        console.log("--- 🕵️ Handshake Failed ---");
        console.log("Final Header used:", socket.request.headers.cookie);
        next();
      });
    });
  });
});

const userStatus = new Map();

io.on("connection", (socket) => {
  const user = socket.request.user;

  // Gate check: user must exist, have an ID, and not be temporary
  if (user && user.id && !user.isTemp) {
    console.log(`✅ Socket connected & registered: User ${user.id}`);

    // 1. Join user's individual room for targeted notifications & direct events
    socket.join(`user_${user.id}`);

    // 2. Normalize estate IDs into an array for multi-estate support
    let estateIds = [];
    if (Array.isArray(user.estate_ids) && user.estate_ids.length > 0) {
      estateIds = user.estate_ids;
    } else if (user.estate_id) {
      estateIds = [user.estate_id];
    }

    // 3. Join all estate-specific rooms the user/admin belongs to
    estateIds.forEach((estateId) => {
      const estateRoom = `estate_${estateId}`;
      socket.join(estateRoom);

      // Notify online status across all their active estates
      socket.to(estateRoom).emit("user_status_change", {
        userId: user.id,
        status: "online",
      });

      // Join admin rooms for every estate they manage
      if (user.role === "ADMIN") {
        const adminRoom = `admins_estate_${estateId}`;
        socket.join(adminRoom);
        console.log(`🛡️ Admin ${user.id} joined ${adminRoom}`);
      }
    });

    userStatus.set(user.id, "online");

    if (user.role === "SUPER_ADMIN") {
      const superAdminRoom = "superadmins";
      socket.join(superAdminRoom);
      console.log(`🛡️ Super Admin ${user.id} joined ${superAdminRoom}`);
    }

    // 4. Handle Guard Location Updates for specific estates
    socket.on("user_location", (locationData) => {
      // Use estate_id sent from payload, or default to user's first estate
      const targetEstateId = locationData.estateId || estateIds[0];
      if (!targetEstateId) return;

      const adminRoom = `admins_estate_${targetEstateId}`;
      io.to(adminRoom).emit("guard_location_update", {
        userId: user.id,
        userName: user.name || user.full_name,
        role: user.role,
        estateId: targetEstateId,
        latitude: locationData.latitude,
        longitude: locationData.longitude,
        address: locationData.address,
        timestamp: locationData.timestamp || Date.now(),
      });
    });

    const currentOnlineInEstate = Array.from(userStatus.keys());
    socket.emit("initial_online_list", currentOnlineInEstate);

    socket.on("typing_start", (targetId) => {
      socket
        .to(`user_${targetId}`)
        .emit("is_typing", { from: user.id, typing: true });
    });

    socket.on("typing_stop", (targetId) => {
      socket
        .to(`user_${targetId}`)
        .emit("is_typing", { from: user.id, typing: false });
    });

    socket.on("initiate_call", (data) => {
      const { targetId, channelName, senderName, senderId } = data;
      socket.to(`user_${targetId}`).emit("incoming_call", {
        channelName,
        senderName,
        senderId,
      });
    });

    socket.on("disconnect", () => {
      userStatus.delete(user.id);
      console.log(`❌ Socket disconnected: User ${user.id}`);

      // Broadcast offline status across all associated estate rooms
      estateIds.forEach((estateId) => {
        socket.to(`estate_${estateId}`).emit("user_status_change", {
          userId: user.id,
          status: "offline",
        });
      });
    });
  } else {
    console.log(`⚠️ Socket connection rejected: Unauthenticated or temp user.`);
  }
});

async function bootServer() {
  try {
    console.log("Pre-loading system security policies into memory...");
    await loadPoliciesIntoMemory(pool);
    console.log("✅ System Policy RAM Cache hydrated successfully.");

    httpServer.listen(3003, "0.0.0.0", () => {
      console.log("🚀 Server running on port 3003");

      // Immediate check on server startup to catch up on any missed rollover
      checkOverstays();
      checkSubscriptionExpirations();
      checkExpiredBookings();
      advanceExpiredProjections().catch((err) =>
        console.error("Failed to run initial projection advancement:", err),
      );

      // 10-Minute Polling
      setInterval(
        () => {
          checkOverstays();
        },
        10 * 60 * 1000,
      );

      // Midnight Rollover Tasks
      cron.schedule("0 0 * * *", async () => {
        console.log(
          "⏰ Running scheduled midnight maintenance & roster projection updates...",
        );
        checkSubscriptionExpirations();

        try {
          await advanceExpiredProjections();
          console.log("✅ Roster projections advanced successfully.");
        } catch (err) {
          console.error(
            "❌ Failed to advance roster projections at midnight:",
            err,
          );
        }
      });

      cron.schedule("5 0 * * *", () => {
        console.log("🧹 Running two-phase expired bookings cleanup...");
        checkExpiredBookings();
      });
    });
  } catch (err) {
    console.error(
      "❌ CRITICAL BOOT FAILURE: Server aborted during initialization.",
      err,
    );
    process.exit(1);
  }
}

bootServer();

export { io };
