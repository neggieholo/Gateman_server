import express from "express";
import passport from "passport";
import firebaseAdmin from "./firebase.js";
import bcrypt from "bcrypt";
import pool from "./db.js";
import { isSuperAdmin, getClientIp, parseUserAgent } from "./middlewares.js";
import { loadPoliciesIntoMemory, getCachedPolicies } from "./policyCache.js";

import { sendRegistrationOTP } from "./emailService.js";
import crypto from "crypto";

const router = express.Router();

const OTP_SECRET = process.env.OTP_SECRET;

router.post("/app/send-otp", async (req, res) => {
  const { target, type, role } = req.body;
  let normalizedTarget;
  if (type === "email") {
    normalizedTarget = target.trim().toLowerCase();
  } else {
    normalizedTarget = target.trim();
  }
  console.log("Generated Normalized Target:", normalizedTarget);

  let tableName;
  let tempTableName = null;

  if (role === "TENANT") {
    tableName = "tenant_users";
    tempTableName = "temp_tenant_users";
  } else if (role === "SECURITY") {
    tableName = "security_users";
    tempTableName = "temp_security_users";
  } else if (role === "ADMIN") {
    tableName = "estate_admin_users";
  } else {
    return res
      .status(400)
      .json({ success: false, message: "Invalid role specified." });
  }

  const checkUser = await pool.query(
    `SELECT id FROM ${tableName} 
       WHERE (LOWER(email) = $1 OR phone = $1)`,
    [normalizedTarget],
  );

  if (checkUser.rows.length > 0) {
    return res.status(400).json({
      success: false,
      message: `This ${type} is already registered to another account.`,
    });
  }

  if (tempTableName) {
    const checkTempUser = await pool.query(
      `SELECT id FROM ${tempTableName} 
         WHERE (LOWER(email) = $1 OR phone = $1)`,
      [normalizedTarget],
    );

    if (checkTempUser.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: `This ${type} is already linked to a pending registration.`,
      });
    }
  }

  const OTP_SECRET = process.env.OTP_SECRET;
  const otp =
    type === "email"
      ? Math.floor(100000 + Math.random() * 900000).toString()
      : "123456";
  const expires = Date.now() + 10 * 60000;

  // Create hash using the target (phone or email)
  const data = `${normalizedTarget}.${otp}.${expires}`;
  const hash = crypto
    .createHmac("sha256", OTP_SECRET)
    .update(data)
    .digest("hex");
  console.log("Generated Data for OTP Hashing:", data);
  console.log("Generated Hash:", hash);
  const metadata = `${hash}.${expires}`;
  console.log("Generate OTP Metadata:", metadata);
  console.log("Generated OTP:", otp);

  try {
    if (type === "email") {
      console.log("send email otp for profile edit");
      const emailSent = await sendRegistrationOTP(target, otp);
      if (emailSent) {
        res.json({ success: true, metadata });
      } else {
        res.status(500).json({ error: "Failed to send email" });
      }
    } else {
      // For phone/SMS, return OTP in dev or call your SMS provider
      return res.json({
        success: true,
        metadata,
        otp: process.env.MODE === "development" ? otp : undefined,
      });
    }
  } catch (err) {
    res.status(500).json({ success: false, message: "Failed to send OTP" });
  }
});

router.post("/otp/send", async (req, res) => {
  console.log("OTP send request received for email:", req.body.email);
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60000;

  const data = `${email}.${otp}.${expires}`;
  const hash = crypto
    .createHmac("sha256", OTP_SECRET)
    .update(data)
    .digest("hex");
  const metadata = `${hash}.${expires}`;

  const emailSent = await sendRegistrationOTP(email, otp);

  if (emailSent) {
    res.json({ success: true, metadata });
  } else {
    res.status(500).json({ error: "Failed to send email" });
  }
});
// ------------------ Register Tenant ------------------
router.post("/register/tenant", async (req, res, next) => {
  console.log("Tenant registration attempt:", req.body.email, req.body.phone);
  const { email, password, name, phone } = req.body;

  try {
    const existingUser = await pool.query(
      `SELECT email FROM tenant_users WHERE LOWER(email) = $1
       UNION SELECT email FROM temp_tenant_users WHERE LOWER(email) = $1`,
      [email.trim().toLowerCase()],
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ error: "Email already registered." });
    }

    // 3. Hash Password and Insert
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO temp_tenant_users (email, phone, password, name, role) 
       VALUES ($1, $2, $3, $4, 'TENANT') RETURNING id, email, name, role`,
      [email.trim().toLowerCase(), phone, passwordHash, name],
    );

    const user = result.rows[0];
    user.isTemp = true;
    user.type = "TENANT";
    user.role = "TENANT";

    req.login(user, (err) => {
      if (err) return next(err);
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        return res.json({
          success: true,
          pending: true,
          message:
            "Tenant registered successfully. Please submit a join request to an estate.",
          user,
        });
      });
    });
  } catch (err) {
    console.error(err);
    console.log("Registration error:", err);
    res.status(500).json({ error: "Registration failed." });
  }
});

router.post("/login/tenant", (req, res, next) => {
  // console.log("tenant login api hit", req.body);
  const { coordinates, deviceMeta } = req.body;
  passport.authenticate("tenant-local", async (err, user, info) => {
    if (err || !user) {
      return res.status(401).json({ error: info?.message });
      console.log("tenant login error", info);
    }

    const currentPolicies = await getCachedPolicies();
    const now = Date.now();

    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);

      req.session.createdAt = now;
      req.session.lastActivityAt = now;

      const ip = getClientIp(req);

      req.session.ip = ip;
      let sessionUserAgent;

      if (deviceMeta) {
        const rawPhone = Array.isArray(deviceMeta.phone)
          ? deviceMeta.phone[0]
          : deviceMeta.phone;
        const brand = rawPhone ? rawPhone.toLowerCase() : "unknown";

        const version = deviceMeta.version || "0";
        const model = deviceMeta.model || "unknown-model";
        const platform = deviceMeta.platform
          ? deviceMeta.platform.toLowerCase()
          : "unknown-platform";

        const tabletSuffix = deviceMeta.isTablet ? "/tablet" : "";

        sessionUserAgent = `${brand}/${version}/${model}/${platform}${tabletSuffix}`;
      } else {
        sessionUserAgent = parseUserAgent(req.headers["user-agent"]);
      }

      req.session.userAgent = sessionUserAgent;
      req.session.coordinates = coordinates || null;

      req.session.save(async (saveErr) => {
        if (saveErr) return next(saveErr);

        let customToken = null;

        if (!user.isTemp) {
          try {
            const postgresUserId = user.id.toString();
            customToken = await firebaseAdmin
              .auth()
              .createCustomToken(postgresUserId, {
                role: "resident",
              });
          } catch (firebaseErr) {
            console.error("Firebase Token Error:", firebaseErr);
          }
        }

        return res.json({
          success: true,
          isTemp: user.isTemp || false,
          user,
          sessionId: req.sessionID,
          chatToken: customToken,
        });
      });
    });
  })(req, res, next);
});

// ------------------ Admin Login ------------------
router.post("/login/admin", (req, res, next) => {
  console.log("Admin auth api hit!");
  const { coordinates } = req.body;

  passport.authenticate("admin-local", async (err, user, info) => {
    if (err) return next(err);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: info?.message || "Invalid credentials",
      });
    }

    // Clean sensitive database attributes from the profile object
    const { passwordHash, mfa_secret, backup_codes, ...safeUser } = user;

    if (!user.is_first_login && user.must_change_password) {
      return res.status(200).json({
        success: false,
        status: "PASSWORD_RESET_REQUIRED",
        message:
          "Administrative reset required. Please update your password immediately.",
      });
    }
    const currentPolicies = await getCachedPolicies();
    const isSubAccount = user.role === "SUB_ADMIN";
    const globalMfaForSubAccounts =
      currentPolicies.require_mfa_for_subaccounts === true;
    const isMfaRequiredByPolicy = isSubAccount && globalMfaForSubAccounts;

    if (user.mfa_enabled) {
      if (user.mfa_type === "EMAIL") {
        return res.status(200).json({
          success: false,
          status: "EMAIL_MFA_REQUIRED",
          user: safeUser,
        });
      }

      if (user.mfa_type === "TOTP") {
        return res.status(200).json({
          success: false,
          status: "TOTP_MFA_REQUIRED",
          user: safeUser,
        });
      }
    } else if (isMfaRequiredByPolicy) {
      if (!user.is_first_login) {
        return res.status(403).json({
          success: false,
          status: "MFA_DEADLINE_MISSED",
          message:
            "Access blocked. Multi-Factor Authentication is required for your role but has not been configured.",
        });
      }
    }

    // Check if we need to flash the dashboard warning flag
    const triggerDashboardPasswordWarning =
      user.is_first_login && user.must_change_password;

    const triggerMfaSetupPrompt = user.is_first_login && isMfaRequiredByPolicy;

    req.login(user, async (err) => {
      if (err) return next(err);

      const now = Date.now();

      if (req.body.rememberMe === true) {
        req.session.cookie.maxAge =
          1000 * 60 * 60 * 24 * currentPolicies.remember_me_duration_days;
        req.session.is_remembered = Boolean(true);
      } else {
        req.session.cookie.maxAge =
          1000 * 60 * currentPolicies.session_timeout_minutes;
      }

      req.session.createdAt = now;
      req.session.lastActivityAt = now;

      const ip = getClientIp(req);

      req.session.ip = ip;
      const clientDevice = parseUserAgent(req.headers["user-agent"]);
      req.session.userAgent = clientDevice;
      req.session.coordinates = coordinates || null;

      await pool.query(
        "UPDATE estate_admin_users SET last_login = NOW() WHERE id = $1",
        [user.id],
      );

      req.session.save((err) => {
        if (err) return next(err);

        return res.json({
          success: true,
          user: safeUser,
          // The Frontend reads this meta block to save flags to localStorage or Context state
          onboarding: {
            showPasswordWarningPopup: triggerDashboardPasswordWarning,
            showMfaSetupOnboarding: triggerMfaSetupPrompt,
          },
        });
      });
    });
  })(req, res, next);
});

// ------------------ Register Security ------------------
router.post("/register/security", async (req, res, next) => {
  const { email, password, name, phone } = req.body;
  // console.log("Security registration attempt for email:", email, "and phone:", phone);

  try {
    const existing = await pool.query(
      `SELECT email FROM security_users WHERE LOWER(email) = $1 OR phone = $2 
       UNION 
       SELECT email FROM temp_security_users WHERE LOWER(email) = $1 OR phone = $2`,
      [email.trim().toLowerCase(), phone.trim()],
    );

    if (existing.rows.length > 0) {
      return res
        .status(400)
        .json({ error: "Email or Phone number already registered." });
    }

    // 3. Insert into TEMP including phone
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO temp_security_users (email, password, name, phone, role) 
       VALUES ($1, $2, $3, $4, 'SECURITY') RETURNING id, email, name, phone, role`,
      [email.trim().toLowerCase(), passwordHash, name, phone.trim()],
    );

    const user = result.rows[0];
    user.isTemp = true;

    req.login(user, (err) => {
      if (err) return next(err);
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        return res.json({ success: true, pending: true, user });
      });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed." });
  }
});

// ------------------ Login Security ------------------
router.post("/login/security", (req, res, next) => {
  console.log("Security login attempt:", req.body.email, req.body.password);
  const { coordinates, deviceMeta } = req.body;

  passport.authenticate("security-local", async (err, user, info) => {
    if (err || !user) {
      console.log("Authentication failed for security:", info);
      return res.status(401).json({ error: info?.message || "Login failed" });
    }

    const currentPolicies = await getCachedPolicies();
    const now = Date.now();

    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);

      req.session.createdAt = now;
      req.session.lastActivityAt = now;

      const ip = getClientIp(req);

      req.session.ip = ip;
      let sessionUserAgent;

      if (deviceMeta) {
        const rawPhone = Array.isArray(deviceMeta.phone)
          ? deviceMeta.phone[0]
          : deviceMeta.phone;
        const brand = rawPhone ? rawPhone.toLowerCase() : "unknown";

        const version = deviceMeta.version || "0";
        const model = deviceMeta.model || "unknown-model";
        const platform = deviceMeta.platform
          ? deviceMeta.platform.toLowerCase()
          : "unknown-platform";

        const tabletSuffix = deviceMeta.isTablet ? "/tablet" : "";

        sessionUserAgent = `${brand}/${version}/${model}/${platform}${tabletSuffix}`;
      } else {
        sessionUserAgent = parseUserAgent(req.headers["user-agent"]);
      }

      req.session.userAgent = sessionUserAgent;
      req.session.coordinates = coordinates || null;

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        return res.json({
          success: true,
          isTemp: user.isTemp || false,
          user,
          sessionId: req.sessionID,
        });
      });
    });
  })(req, res, next);
});

router.post("/login/super-admin", (req, res, next) => {
  console.log("Super admin auth api hit!");
  const { coordinates } = req.body;

  passport.authenticate("super-admin-local", async (err, user, info) => {
    if (err) return next(err);

    if (!user) {
      return res.status(401).json({
        success: false,
        error: info?.message || "Invalid credentials",
      });
    }

    // Clean sensitive database attributes from the profile object
    const { password_hash, mfa_secret, backup_codes, ...safeUser } = user;

    if (!user.is_first_login && user.must_change_password) {
      return res.status(200).json({
        success: false,
        status: "PASSWORD_RESET_REQUIRED",
        message:
          "Administrative reset required. Please update your password immediately.",
      });
    }
    const currentPolicies = await getCachedPolicies();
    const isSubAccount = user.role === "SUB_ADMIN";
    const globalMfaForSubAccounts =
      currentPolicies.require_mfa_for_subaccounts === true;
    const isMfaRequiredByPolicy = isSubAccount && globalMfaForSubAccounts;

    const estatesRes = await pool.query(
      "SELECT id, name FROM estates ORDER BY name ASC",
    );
    const estatesList = estatesRes.rows;

    if (user.mfa_enabled) {
      if (user.mfa_type === "EMAIL") {
        return res.status(200).json({
          success: false,
          status: "EMAIL_MFA_REQUIRED",
          user: safeUser,
          estatesList,
        });
      }

      if (user.mfa_type === "TOTP") {
        return res.status(200).json({
          success: false,
          status: "TOTP_MFA_REQUIRED",
          user: safeUser,
          estatesList,
        });
      }
    } else if (isMfaRequiredByPolicy) {
      if (!user.is_first_login) {
        return res.status(403).json({
          success: false,
          status: "MFA_DEADLINE_MISSED",
          message:
            "Access blocked. Multi-Factor Authentication is required for your role but has not been configured.",
        });
      }
    }

    // STANDARD ACCESS PROTOCOL: Fall through if MFA passed/absent
    let clientIsFirstLogin = safeUser.is_first_login;

    // Check if we need to flash the dashboard warning flag
    const triggerDashboardPasswordWarning =
      user.is_first_login && user.must_change_password;

    const triggerMfaSetupPrompt = user.is_first_login && isMfaRequiredByPolicy;

    req.login(user, async (err) => {
      if (err) return next(err);

      const now = Date.now();

      if (req.body.rememberMe === true) {
        req.session.cookie.maxAge =
          1000 * 60 * 60 * 24 * currentPolicies.remember_me_duration_days;
          // req.session.is_remembered = Boolean(true);
      } else {
        req.session.cookie.maxAge =
          1000 * 60 * currentPolicies.session_timeout_minutes;
      }

      req.session.createdAt = now;
      req.session.lastActivityAt = now;

      const ip = getClientIp(req);

      req.session.ip = ip;
      const clientDevice = parseUserAgent(req.headers["user-agent"]);
      req.session.userAgent = clientDevice;
      req.session.coordinates = coordinates || null;

      await pool.query(
        "UPDATE super_admins SET last_login = NOW() WHERE id = $1",
        [user.id],
      );

      req.session.save((err) => {
        if (err) return next(err);

        return res.json({
          success: true,
          user: { ...safeUser },
          estatesList,
          onboarding: {
            showPasswordWarningPopup: triggerDashboardPasswordWarning,
            showMfaSetupOnboarding: triggerMfaSetupPrompt,
          },
        });
      });
    });
  })(req, res, next);
});

export default router;
