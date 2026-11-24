// routes/master.js
import express from "express";
import pool from "./db.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { createAuditLog } from "./helpers.js";
import {
  isAuth,
  isSuperAdmin,
  hasPermission,
  verifyPermission,
  parseUserAgent,
  getClientIp,
} from "./middlewares.js";
import { generateSecret, generateURI, verify } from "otplib";
import {
  sendAdminWelcomeEmail,
  sendPasswordResetCode,
  sendRegistrationOTP,
} from "./emailService.js";
import { loadPoliciesIntoMemory, getCachedPolicies } from "./policyCache.js";

const router = express.Router();

router.post("/verify-login-otp", async (req, res, next) => {
  // 1. Destructure rememberMe from the inbound request payload body
  const { otp, metadata, target, type, rememberMe, coordinates } = req.body;

  try {
    const normalizedTarget = target.trim().toLowerCase();

    // Fetch full admin details to process login parameters
    const dbQuery = await pool.query(
      "SELECT * FROM super_admins WHERE LOWER(email) = $1",
      [normalizedTarget],
    );
    const user = dbQuery.rows[0];

    if (!user) {
      return res
        .status(401)
        .json({ success: false, message: "Verification context error." });
    }

    // 2. RUN CONDITIONAL MATCHING PROCEDURES BASED ON MFA SELECTION
    if (type === "email") {
      const [hash, expires] = metadata.split(".");

      if (Date.now() > parseInt(expires)) {
        return res
          .status(400)
          .json({ success: false, message: "OTP expired. Please resend." });
      }

      const data = `${normalizedTarget}.${otp}.${expires}`;
      const verifyHash = crypto
        .createHmac(
          "sha256",
          "0022c30a40599aae79fb6a7ea31bf742a11b9618663521f0dea2f94954de2dbb",
        )
        .update(data)
        .digest("hex");

      if (verifyHash !== hash) {
        return res.json({ success: false, message: "Invalid OTP code." });
      }

      await pool.query(
        "UPDATE super_admins SET email_verified = true WHERE id = $1",
        [user.id],
      );

      user.email_verified = true;
    } else if (type === "totp") {
      // Clean up any stray whitespaces from user input
      const cleanOtp = String(otp).trim().replace(/\s+/g, "");
      // console.log("Cleaned OTP for TOTP Verification:", cleanOtp);
      const result = await verify({
        secret: user.mfa_secret,
        token: cleanOtp,
      });

      if (!result.valid) {
        return res.json({
          success: false,
          message: "Invalid authenticator application token.",
        });
      }
    } else {
      return res.status(400).json({
        success: false,
        message: "Unsupported validation variant protocol.",
      });
    }

    // First login normalization check (parallels logic from /login/super-admin)
    let clientIsFirstLogin = user.is_first_login;
    if (user.is_first_login) {
      await pool.query(
        "UPDATE super_admins SET is_first_login = false WHERE id = $1",
        [user.id],
      );
      clientIsFirstLogin = true;
    }

    req.login(user, async (err) => {
      if (err) return next(err);

      const currentPolicies = getCachedPolicies();
      const now = Date.now();

      const rememberMeDays =
        Number(currentPolicies.remember_me_duration_days) || 30;
      const timeoutMinutes =
        Number(currentPolicies.session_timeout_minutes) || 15;

      if (rememberMe === true) {
        req.session.cookie.maxAge = 1000 * 60 * 60 * 24 * rememberMeDays;
      } else {
        req.session.cookie.maxAge = 1000 * 60 * timeoutMinutes;
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

      const estatesRes = await pool.query(
        "SELECT id, name FROM estates ORDER BY name ASC",
      );
      const estatesList = estatesRes.rows;

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        const { password_hash, mfa_secret, backup_codes, ...safeUser } = user;
        return res.json({
          success: true,
          user: { ...safeUser, is_first_login: clientIsFirstLogin },
          estatesList,
        });
      });
    });
  } catch (err) {
    console.error("Verification Route Failure:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server validation engine failure.",
    });
  }
});

router.post("/forgot-password", async (req, res) => {
  const { email } = req.body;
  console.log(
    `[Super Admin Forgot Password] Request initialized for endpoint signature: ${email}`,
  );

  if (!email) {
    return res.status(400).json({
      success: false,
      message: "Email signature registration footprint is required.",
    });
  }

  const cleanEmail = email.trim().toLowerCase();

  try {
    // Target the core super admin isolation database mapping
    const result = await pool.query(
      `SELECT id, email, full_name FROM public.super_admins WHERE LOWER(email) = $1 AND is_active = true`,
      [cleanEmail],
    );
    const user = result.rows[0];

    if (!user) {
      console.log(
        `[Super Admin Forgot Password] Enumeration warning: Target footprint "${cleanEmail}" does not exist.`,
      );
      return res.json({
        success: true,
        message: "Reset link sent! Please check your email inbox.",
      });
    }

    // Generate crypto token sequence
    const resetToken = crypto.randomBytes(32).toString("hex");

    // Enforce 1 hour constraint window onto database token vector
    await pool.query(
      `UPDATE super_admins 
       SET reset_token = $1, reset_token_expiry = NOW() + INTERVAL '1 hour' 
       WHERE id = $2`,
      [resetToken, user.id],
    );

    // Build absolute route target link to master workstation login view
    const resetLink = `https://gatemanhq.com/passwordReset/super_admin/${user.id}/${resetToken}`;

    const emailSent = await sendPasswordResetCode(cleanEmail, resetLink);

    if (emailSent) {
      return res.json({
        success: true,
        message: "Reset link sent! Please check your email inbox.",
      });
    } else {
      return res.status(500).json({
        success: false,
        message: "Email core service outbound dispatch failed.",
      });
    }
  } catch (error) {
    console.error("Super Admin Forgot Password Core Error:", error);
    return res.status(500).json({
      success: false,
      message: "Server error.",
    });
  }
});

// ─── POST: EXECUTE SUPER ADMIN PASSWORD RESET OVERRIDE WRITE ───
router.post("/reset-password", async (req, res) => {
  const { token, password, userId } = req.body;

  if (!token || !password || !userId) {
    return res.status(400).json({
      success: false,
      message: "Missing required operational token tracking fields.",
    });
  }

  const client = await pool.connect();

  try {
    // 1. Verify verification link token constraints FIRST
    const userQuery = await client.query(
      `SELECT id, password_hash FROM super_admins 
       WHERE id = $1 AND reset_token = $2 AND reset_token_expiry > NOW() AND is_active = true`,
      [userId, token],
    );

    if (userQuery.rows.length === 0) {
      client.release();
      return res.status(400).json({
        success: false,
        message: "Invalid or expired administrative recovery token sequence.",
      });
    }

    const currentAdmin = userQuery.rows[0];

    // 2. Password Reuse Prevention Check
    const policySettings = await getCachedPolicies();
    const reuseLimit = policySettings.pwd_prevent_reuse_count || 0;

    if (reuseLimit > 0) {
      // Fetch previous hashes using pool/client (fixed 'db' reference)
      const previousPasswords = await client.query(
        `SELECT password_hash FROM password_histories 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT $2`,
        [userId, reuseLimit],
      );

      // Compare incoming 'password' (fixed 'newPlainTextPassword' reference)
      for (let row of previousPasswords.rows) {
        const matchesOld = await bcrypt.compare(password, row.password_hash);
        if (matchesOld) {
          client.release();
          return res.status(400).json({
            success: false,
            message: `You cannot reuse any of your last ${reuseLimit} passwords.`,
          });
        }
      }
    }

    // 3. Hash New Password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 4. BEGIN TRANSACTION
    await client.query("BEGIN");

    // Save old hash into history before overwriting
    if (currentAdmin.password_hash) {
      await client.query(
        `INSERT INTO password_histories (user_id, password_hash, created_at)
         VALUES ($1, $2, NOW())`,
        [userId, currentAdmin.password_hash],
      );
    }

    // Clear reset vectors, update password, and clear force-change flags
    await client.query(
      `UPDATE super_admins 
       SET 
         password_hash = $1, 
         reset_token = NULL, 
         reset_token_expiry = NULL, 
         must_change_password = false,
         updated_at = CURRENT_TIMESTAMP
       WHERE id = $2`,
      [hashedPassword, userId],
    );

    await client.query("COMMIT");

    console.log(
      `[Auth Mastery] Secure password configuration reset processed for Super Admin ID: ${userId}`,
    );

    return res.json({
      success: true,
      message: "Credentials updated successfully. Proceed to login panel.",
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Super Admin Password Reset System Error:", error);
    return res.status(500).json({
      success: false,
      message: "Internal server error resetting admin credentials context.",
    });
  } finally {
    client.release();
  }
});

router.use(isSuperAdmin);
router.use(isAuth);

router.post("/send-otp", async (req, res) => {
  const { target, type } = req.body;
  const adminId = req.user.id;
  let normalizedTarget;
  if (type === "email") {
    normalizedTarget = target.trim().toLowerCase();
  } else {
    normalizedTarget = target.trim();
  }
  // console.log("Generated Normalized Target:", normalizedTarget);

  const checkUser = await pool.query(
    `SELECT id FROM super_admins 
       WHERE (LOWER(email) = $1 OR phone_number = $1) 
       AND id != $2`,
    [normalizedTarget, adminId],
  );

  if (checkUser.rows.length > 0) {
    return res.status(400).json({
      success: false,
      message: `This ${type} is already registered to another account.`,
    });
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

router.post("/mfa/setup", async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    const secret = generateSecret();

    const uri = generateURI({
      issuer: "GateMan HQ",
      label: req.user.email,
      secret: secret,
    });

    return res.json({
      success: true,
      secret: secret,
      qrCodeUri: uri,
    });
  } catch (err) {
    console.error("MFA Setup Error:", err);
    return res.status(500).json({ success: false, message: "Server error" });
  }
});

// ENDPOINT 2: Confirm handshake and activate
router.post("/mfa/verify-totp", async (req, res) => {
  const { token, secret } = req.body;

  try {
    const result = await verify({
      secret: secret,
      token: token.trim(),
    });

    if (result.valid) {
      await pool.query(
        `UPDATE super_admins 
         SET mfa_enabled = true, 
             mfa_type = 'TOTP', 
             mfa_secret = $1 
         WHERE id = $2`,
        [secret, req.user.id],
      );

      return res.json({
        success: true,
        message: "Authenticator application linked and activated successfully!",
      });
    } else {
      return res.json({
        success: false,
        message: "Invalid verification code. Try again.",
      });
    }
  } catch (err) {
    console.error("MFA Activation Error:", err);
    return res
      .status(500)
      .json({ success: false, message: "Activation failed" });
  }
});

router.post("/verify-totp", async (req, res, next) => {
  const { otp } = req.body;

  try {
    const user = req.user; // Or fetch from session/db using user ID
    if (!user || !user.mfa_secret) {
      return res.status(400).json({
        success: false,
        message: "User session or MFA secret not found.",
      });
    }

    // 2. Clean and format OTP input
    const cleanOtp = String(otp || "")
      .trim()
      .replace(/\s+/g, "");

    const result = await verify({
      secret: user.mfa_secret,
      token: cleanOtp,
    });

    if (!result.valid) {
      return res.status(400).json({
        success: false,
        message: "Invalid authenticator application token.",
      });
    }
    return res.json({
      success: true,
      message: "TOTP verified and MFA preference updated successfully.",
    });
  } catch (err) {
    console.error("Verification Route Failure:", err);
    return res.status(500).json({
      success: false,
      message: "Internal server validation engine failure.",
    });
  }
});

router.post("/update-config", isSuperAdmin, async (req, res) => {
  const { config } = req.body;

  if (!config) {
    return res
      .status(400)
      .json({ success: false, message: "Missing configuration payload" });
  }

  const adminId = req.user.id;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Targets the 'super_admins' table based on your schema layout
    const updateQuery = `
      UPDATE super_admins 
      SET 
        full_name = COALESCE($1, full_name), 
        email = COALESCE($2, email), 
        phone_number = COALESCE($3, phone_number),
        mfa_enabled = COALESCE($4, mfa_enabled),
        mfa_type = COALESCE($5, mfa_type),
        avatar_url = COALESCE($6, avatar_url),
        email_verified = $7,
        phone_verified = $8,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $9 
      RETURNING id, full_name, email, role, mfa_enabled, mfa_type, wallet_balance, permissions, is_active;
    `;

    const updateValues = [
      config.admin_name || req.user.full_name,
      config.email || req.user.email,
      config.phone_number || req.user.phone_number,
      config.mfa_enabled !== undefined
        ? config.mfa_enabled
        : req.user.mfa_enabled,
      config.mfa_type ? config.mfa_type.toUpperCase() : req.user.mfa_type,
      config.avatar_url || req.user.avatar_url,
      config.email ? true : req.user.email_verified,
      config.phone ? true : req.user.phone_verified,
      adminId,
    ];

    const result = await client.query(updateQuery, updateValues);

    if (result.rows.length === 0) {
      await client.query("ROLLBACK");
      return res
        .status(404)
        .json({ success: false, message: "Super admin record not found" });
    }

    await client.query("COMMIT");

    // Return payload to sync your frontend Context state
    res.json({
      success: true,
      message: "Configuration saved!",
      user: result.rows[0],
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Master Config Update Error:", err);
    res.status(500).json({ success: false, message: "Internal server error" });
  } finally {
    client.release();
  }
});

// ─── NEW: FETCH ALL GRANULAR SYSTEM PERMISSIONS ───
router.get(
  "/system-permissions",
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, name, parent_permission FROM system_permissions 
       ORDER BY COALESCE(parent_permission, id), parent_permission IS NOT NULL, id`,
      );

      return res.json({
        success: true,
        permissions: result.rows,
      });
    } catch (err) {
      console.error("Fetch System Permissions Operational Failure:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal server error fetching structural permissions dictionary.",
      });
    }
  },
);

// ─── NEW: FETCH ALL CUSTOM ROLE PRESET TEMPLATES ───
router.get(
  "/custom-roles",
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT id, role_name, description, permission_ids 
       FROM public.custom_roles 
       ORDER BY role_name ASC`,
      );

      return res.json({
        success: true,
        roles: result.rows,
      });
    } catch (err) {
      console.error("Fetch Custom Roles Operational Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error fetching saved custom role matrices.",
      });
    }
  },
);

// ─── NEW: CREATE/SAVE A REUSABLE CUSTOM ROLE BLUEPRINT ───
router.post(
  "/custom-roles",
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    const { role_name, description, permission_ids } = req.body;

    if (
      !role_name ||
      !Array.isArray(permission_ids) ||
      permission_ids.length === 0
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid configuration payload. Role name and permission tokens are required.",
      });
    }

    try {
      const cleanName = role_name.trim();

      // Check if configuration profile exists to prevent uniquely violations
      const checkExist = await pool.query(
        "SELECT id FROM public.custom_roles WHERE LOWER(role_name) = LOWER($1)",
        [cleanName],
      );
      if (checkExist.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message:
            "A custom role template with this name signature already exists.",
        });
      }

      const insertQuery = `
      INSERT INTO public.custom_roles (role_name, description, permission_ids)
      VALUES ($1, $2, $3::VARCHAR(50)[])
      RETURNING id, role_name, description, permission_ids;
    `;

      const result = await pool.query(insertQuery, [
        cleanName,
        description || null,
        permission_ids,
      ]);

      const createdRole = result.rows[0];

      await createAuditLog(req, {
        action_type: "CREATE_ROLE_TEMPLATE",
        target_resource: "custom_roles",
        target_id: createdRole.id,
        description: `Created new reusable custom role blueprint schema template: "${cleanName}"`,
        state_before: null,
        state_after: createdRole,
        log_type: "user",
      });

      return res.status(201).json({
        success: true,
        message: "Custom role template matrix stored successfully.",
        role: result.rows[0],
      });
    } catch (err) {
      console.error("Save Custom Role Operational Failure:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal database failure writing custom authorization mapping profile.",
      });
    }
  },
);

// ─── CREATE/ONBOARD SUPER ADMINISTRATIVE USER WORKSPACE ───
router.post(
  "/admins/create",
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    const {
      full_name,
      email,
      phone_number,
      require_password_change,
      sub_account,
      permissions,
    } = req.body;

    if (!full_name || !email || !Array.isArray(permissions)) {
      return res.status(400).json({
        success: false,
        message:
          "Missing core operational identification parameters or authorization arrays.",
      });
    }

    try {
      const cleanEmail = email.trim().toLowerCase();

      // 🔐 Check existing email in super_admins
      const checkExist = await pool.query(
        "SELECT id FROM super_admins WHERE LOWER(email) = $1",
        [cleanEmail],
      );
      if (checkExist.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message:
            "A super administrative profile with this email address already exists.",
        });
      }

      // Check existing phone number if provided
      if (phone_number) {
        const checkPhoneExist = await pool.query(
          "SELECT id FROM super_admins WHERE LOWER(phone_number) = $1",
          [phone_number.trim()],
        );
        if (checkPhoneExist.rows.length > 0) {
          return res.status(400).json({
            success: false,
            message:
              "A super administrative profile with this phone number already exists.",
          });
        }
      }

      // 🔑 Generate secure password parts internally
      const emailPasswordPart = crypto.randomBytes(3).toString("hex");
      const smsPasswordPart = "gate";
      const fullCombinedPassword = emailPasswordPart + smsPasswordPart;

      const passwordHash = await bcrypt.hash(fullCombinedPassword, 10);

      // 🚀 Insert record with first_login = true
      const insertQuery = `
        INSERT INTO super_admins (
          full_name, email, password_hash, phone_number, 
          must_change_password, sub_account, permissions, is_first_login
        ) VALUES ($1, $2, $3, $4, $5, $6, $7::VARCHAR(50)[], true)
        RETURNING 
          id, full_name, email, phone_number, 
          must_change_password, sub_account, permissions, is_first_login,
          email_verified, phone_verified, created_at;
      `;

      const result = await pool.query(insertQuery, [
        full_name.trim(),
        cleanEmail,
        passwordHash,
        phone_number ? phone_number.trim() : null,
        require_password_change ?? true,
        sub_account ?? true,
        permissions,
      ]);

      const createdAdmin = result.rows[0];

      // 📝 Commit audit log
      await createAuditLog(req, {
        action_type: "CREATE_ADMIN",
        target_resource: "super_admins",
        target_id: createdAdmin.id,
        description: `Successfully built managed super admin profile for ${createdAdmin.full_name} (${cleanEmail}).`,
        state_before: null,
        state_after: createdAdmin,
        log_type: "user",
      });

      // ✉️ Dispatch credentials based on presence of phone number
      if (phone_number) {
        try {
          await sendAdminWelcomeEmail(
            cleanEmail,
            full_name.trim(),
            emailPasswordPart,
            require_password_change ?? true,
            true,
          );
          console.log(
            `Super admin email credential part dispatched to ${cleanEmail}`,
          );
        } catch (mailErr) {
          console.error("⚠️ Background notice dispatch failed:", mailErr);
        }

        console.log(
          `[TEST MODE SMS TOKEN SIMULATION] Phone: ${phone_number} | Token: ${smsPasswordPart}`,
        );
      } else {
        try {
          await sendAdminWelcomeEmail(
            cleanEmail,
            full_name.trim(),
            fullCombinedPassword,
            require_password_change ?? true,
            false,
          );
          console.log(
            `Full super admin email credentials dispatched to ${cleanEmail}`,
          );
        } catch (mailErr) {
          console.error("⚠️ Background notice dispatch failed:", mailErr);
        }
      }

      return res.status(201).json({
        success: true,
        message: "Super administrative profile built successfully.",
        admin: createdAdmin,
      });
    } catch (err) {
      console.error(
        "Onboard Super Admin Workspace Error Exception Handler:",
        err,
      );
      return res.status(500).json({
        success: false,
        message:
          "Internal server structural database execution error creating profile.",
      });
    }
  },
);

// ─── FETCH ALL FORENSIC USER LOGS WITH FILTER SLICES ───
router.post(
  "/user-logs",
  verifyPermission("view_user_logs", "users_management"),
  async (req, res) => {
    const { type } = req.body;

    if (!type) {
      return res.status(400).json({
        success: false,
        message: "Missing required body parameter: type",
      });
    }

    try {
      const {
        action_type,
        target_resource,
        limit = 100,
        offset = 0,
      } = req.body;

      // 1. Seed the array with 'type' so it safely matches $1 from the jump
      const queryParams = [type];

      let queryStr = `
        SELECT 
          id, user_id, user_name, user_email, 
          action_type, target_resource, target_id, 
          description, state_before, state_after, 
          ip_address, user_agent, created_at
        FROM logs
        WHERE log_type = $1
      `;

      // 2. Safely increment placeholders ($2, $3, etc.)
      if (action_type) {
        queryParams.push(action_type);
        queryStr += ` AND action_type = $${queryParams.length}`;
      }
      if (target_resource) {
        queryParams.push(target_resource);
        queryStr += ` AND target_resource = $${queryParams.length}`;
      }

      // 3. Push limit and offset values
      queryParams.push(parseInt(limit, 10), parseInt(offset, 10));

      // Calculate index dynamically based on array length
      queryStr += ` ORDER BY created_at DESC LIMIT $${queryParams.length - 1} OFFSET $${queryParams.length}`;

      // 4. Pass the array directly without re-appending 'type'
      const result = await pool.query(queryStr, queryParams);

      return res.json({
        success: true,
        count: result.rows.length,
        logs: result.rows,
      });
    } catch (err) {
      console.error("Fetch User Logs Operational Failure:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal server error gathering structural system activity logs.",
      });
    }
  },
);

// ─── FETCH ALL SUPER ADMINISTRATIVE ACCOUNTS ───
router.get(
  "/admins",
  verifyPermission("view_users", "users_management"),
  async (req, res) => {
    try {
      const userPermissions = req.user?.permissions || [];
      const hasAllAccess = userPermissions.includes("all-access");

      // 🎯 Select fields updated to include permissions, verification flags, and is_active instead of status
      let queryStr = `
        SELECT 
          id, 
          full_name, 
          email, 
          phone_number, 
          mfa_enabled, 
          mfa_type, 
          sub_account, 
          permissions,
          phone_verified,
          email_verified,
          is_active,
          avatar_url,
          created_at
        FROM super_admins
        WHERE id != $1
      `;
      const queryParams = [req.user.id];

      // If the administrator does NOT have 'all-access', enforce strict sub-account filtering
      if (!hasAllAccess) {
        queryStr += ` AND sub_account = true`;
      }

      // Order chronologically by newest accounts first
      queryStr += ` ORDER BY created_at DESC`;

      const result = await pool.query(queryStr, queryParams);

      return res.json({
        success: true,
        count: result.rows.length,
        users: result.rows, // Matches your updated frontend layout interface
      });
    } catch (err) {
      console.error("Fetch Admins Registry Operational Failure:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal server error gathering structural administrator records.",
      });
    }
  },
);

// ─── NEW: UPDATE GRANULAR PRIVILEGES FOR AN ADMISTRATOR NODE ───
router.put(
  "/:userId/permissions",
  verifyPermission("modify_user_permissions", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const { permissions } = req.body;

    if (!Array.isArray(permissions)) {
      return res.status(400).json({
        success: false,
        message: "Wrong format",
      });
    }

    const operatorId = req.user.id;

    if (String(userId) === String(operatorId)) {
      return res.status(403).json({
        success: false,
        message:
          "Privilege Escalation Protection: Self permission updates are explicitly restricted.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const snapshotQuery = `
        SELECT id, full_name, email, permissions 
        FROM super_admins 
        WHERE id = $1
      `;

      const snapshotResult = await client.query(snapshotQuery, [userId]);

      if (snapshotResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message:
            "Target administrator record could not be mapped within current workspace database.",
        });
      }

      const targetAdmin = snapshotResult.rows[0];

      const updateQuery = `
        UPDATE super_admins
        SET 
          permissions = $1::VARCHAR(50)[],
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        RETURNING id, full_name, email, permissions, updated_at;
      `;

      const result = await client.query(updateQuery, [permissions, userId]);
      const updatedAdmin = result.rows[0];

      // 🎯 Step 3: Write structural forensic security trail log footprint
      await createAuditLog(req, {
        action_type: "MUTATE_USER_PERMISSIONS",
        target_resource: "super_admins",
        target_id: updatedAdmin.id,
        description: `Reconfigured granular feature access authorization matrix for admin: "${updatedAdmin.full_name}" (${updatedAdmin.email})`,
        state_before: { permissions: targetAdmin.permissions },
        state_after: { permissions: updatedAdmin.permissions },
        log_type: "user",
      });

      await client.query("COMMIT");

      return res.json({
        success: true,
        message:
          "Administrative privileges synchronized and logged successfully.",
        user: {
          id: updatedAdmin.id,
          full_name: updatedAdmin.full_name,
          email: updatedAdmin.email,
          permissions: updatedAdmin.permissions,
        },
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error(
        "Modify Admin Permissions Operational Failure Matrix:",
        err,
      );
      return res.status(500).json({
        success: false,
        message:
          "Internal database failure restructuring administrator authorization permissions map.",
      });
    } finally {
      client.release();
    }
  },
);

// 🚀 Enforced isSuperAdmin authorization layer security guard
router.post("/change-password", async (req, res) => {
  const { currentPassword, newPassword } = req.body;

  if (!currentPassword || !newPassword) {
    return res.status(400).json({
      success: false,
      message: "Current and new passwords are required",
    });
  }

  const client = await pool.connect();

  try {
    const userId = req.user?.id;

    if (!userId) {
      client.release();
      return res.status(401).json({ success: false, message: "Unauthorized" });
    }

    // 1. Fetch current super admin record
    const userResult = await client.query(
      `SELECT password_hash, must_change_password FROM super_admins WHERE id = $1`,
      [userId],
    );

    if (userResult.rows.length === 0) {
      client.release();
      return res
        .status(404)
        .json({ success: false, message: "Super admin record not found" });
    }

    const currentAdmin = userResult.rows[0];
    const storedHash = currentAdmin.password_hash;

    // 2. Verify Current Password FIRST
    const isMatch = await bcrypt.compare(currentPassword, storedHash);
    if (!isMatch) {
      client.release();
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    // 3. Password Reuse Prevention Check
    const policySettings = await getCachedPolicies();
    const reuseLimit = policySettings.pwd_prevent_reuse_count || 0;

    if (reuseLimit > 0) {
      const previousPasswords = await client.query(
        `SELECT password_hash FROM password_histories 
         WHERE user_id = $1 
         ORDER BY created_at DESC 
         LIMIT $2`,
        [userId, reuseLimit],
      );

      for (let row of previousPasswords.rows) {
        const matchesOld = await bcrypt.compare(newPassword, row.password_hash);
        if (matchesOld) {
          client.release();
          return res.status(400).json({
            success: false,
            message: `You cannot reuse any of your last ${reuseLimit} passwords.`,
          });
        }
      }
    }

    // 4. Hash New Password
    const saltRounds = 10;
    const newHash = await bcrypt.hash(newPassword, saltRounds);

    // 5. BEGIN TRANSACTION (Update Admin + Save Old/New Hash in History)
    await client.query("BEGIN");

    // Save the old password hash into history (if it isn't already there)
    await client.query(
      `INSERT INTO password_histories (user_id, password_hash, created_at)
       VALUES ($1, $2, NOW())`,
      [userId, storedHash],
    );

    // Update Super Admin credentials
    const updateQuery = `
      UPDATE super_admins 
      SET 
        password_hash = $1, 
        must_change_password = false,
        updated_at = CURRENT_TIMESTAMP
      WHERE id = $2
      RETURNING 
        id, 
        full_name, 
        email, 
        phone_number, 
        phone_verified, 
        email_verified, 
        role, 
        wallet_balance, 
        mfa_enabled, 
        mfa_type, 
        permissions, 
        is_active, 
        last_login, 
        created_at, 
        avatar_url,
        must_change_password;
    `;

    const result = await client.query(updateQuery, [newHash, userId]);
    const updatedAdmin = result.rows[0];

    await client.query("COMMIT");

    // 6. Audit Logging
    await createAuditLog(req, {
      action_type: "CHANGE_PASSWORD",
      target_resource: "super_admins",
      target_id: userId,
      description: `Successfully modified root credentials and updated password history.`,
      state_before: { must_change_password: currentAdmin.must_change_password },
      state_after: { must_change_password: updatedAdmin.must_change_password },
      log_type: "user",
    });

    console.log(
      `[Auth] Password modified and history updated for Super Admin ID: ${userId}`,
    );

    return res.json({
      success: true,
      message: "Password updated successfully, setup flag cleared.",
      user: updatedAdmin,
    });
  } catch (error) {
    await client.query("ROLLBACK");
    console.error(
      "Super Admin Change Password Operational Failure Exception:",
      error,
    );
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  } finally {
    client.release();
  }
});

// ─── POST: ADMINISTRATIVE EXPLICIT PASSWORD OVERRIDE BYPASS ───
router.post(
  "/:subAccountId/override-password",
  verifyPermission("modify_users_pass", "users_management"),
  async (req, res) => {
    const { subAccountId } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.trim().length < 6) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid payload. A secure override password configuration value is required.",
      });
    }

    const operatorId = req.user.id;

    // 🛡️ Guard: Self-override protection loop intercept
    if (String(subAccountId) === String(operatorId)) {
      return res.status(403).json({
        success: false,
        message:
          "Operation restricted. Use the personal account config panel to update your own keys.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const targetQuery = `SELECT id, full_name, email FROM super_admins WHERE id = $1`;
      const targetResult = await client.query(targetQuery, [subAccountId]);

      if (targetResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message:
            "Target sub-account record could not be mapped within database workspace.",
        });
      }

      const subAccount = targetResult.rows[0];

      // Hash the override password allocation credential cleanly
      const hashedPassword = await bcrypt.hash(newPassword, 10);

      const updateQuery = `
        UPDATE super_admins
        SET 
          password_hash = $1,
          must_change_password = true, 
          is_first_login = true,
          reset_token = NULL,
          reset_token_expiry = NULL,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
      `;
      await client.query(updateQuery, [hashedPassword, subAccountId]);

      // Write forensic trail log record footprint
      await createAuditLog(req, {
        action_type: "FORCE_RESET_USER_PASSWORD",
        target_resource: "super_admins",
        target_id: subAccountId,
        description: `Master Super Admin explicitly updated password parameters for managed sub-account entry: "${subAccount.full_name}" (${subAccount.email}) and enforced renewal sequence flags.`,
        state_before: null,
        state_after: null,
        log_type: "user",
      });

      await client.query("COMMIT");

      await client.query(
        `DELETE FROM session 
        WHERE sess->'passport'->'user'->>'id' = $1`,
        [subAccountId],
      );
      return res.json({
        success: true,
        message: `Credentials reconfigured successfully for ${subAccount.full_name}. User will be prompted to renew password on next workspace login initialization.`,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Administrative Override Force Failure Matrix:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal transactional error committing administrative credential override.",
      });
    } finally {
      client.release();
    }
  },
);

// ─── PUT: ALTER SECURITY MFA DESIGNATION POLICY (ENABLE / DISABLE ONLY) ───
router.put(
  "/:userId/mfa-policy",
  verifyPermission("modify_users_mfa", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const { mfa_enabled } = req.body;

    // Validate that the request explicitly included the boolean flag
    if (mfa_enabled === undefined) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid configuration payload. Specify desired mfa_enabled policy setting boolean flag value.",
      });
    }

    const operatorId = req.user.id;

    // 🛡️ Guard: Block operators from disabling their own MFA to prevent security degradation loops
    if (String(userId) === String(operatorId) && !mfa_enabled) {
      return res.status(403).json({
        success: false,
        message:
          "Self-protection loop triggered: You cannot bypass your own active account MFA controls from this workstation.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Verify profile target row exists and fetch historical state for logging
      const checkAdmin = await client.query(
        "SELECT id, full_name, email, mfa_enabled FROM super_admins WHERE id = $1",
        [userId],
      );

      if (checkAdmin.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message:
            "Target administrator context could not be located inside current workspace repository.",
        });
      }

      const targetUser = checkAdmin.rows[0];

      // 2. Persist ONLY mfa_enabled down to the core user row (preserving mfa_type)
      const updateQuery = `
        UPDATE super_admins
        SET 
          mfa_enabled = $1,
          updated_at = CURRENT_TIMESTAMP
        WHERE id = $2
        RETURNING id, full_name, email, mfa_enabled, mfa_type;
      `;
      const result = await client.query(updateQuery, [mfa_enabled, userId]);
      const updatedAdmin = result.rows[0];

      // 3. File a detailed digital footprint audit log entry
      await createAuditLog(req, {
        action_type: mfa_enabled ? "ENFORCE_USER_MFA" : "DISABLE_USER_MFA",
        target_resource: "super_admins",
        target_id: userId,
        description: `Modified authentication profile: Forcibly toggled MFA restriction state for administrator node "${targetUser.full_name}" to [${mfa_enabled ? "ENABLED" : "DISABLED"}]. Underlying registration method preserved.`,
        state_before: { mfa_enabled: targetUser.mfa_enabled },
        state_after: { mfa_enabled: updatedAdmin.mfa_enabled },
        log_type: "user",
      });

      await client.query("COMMIT");
      return res.json({
        success: true,
        message: mfa_enabled
          ? "MFA policy rules successfully re-enforced."
          : "MFA safety bypass flag successfully activated.",
        user: updatedAdmin,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("MFA Policy Shift System Error Matrix Failure:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal server error altering core database security criteria matrix values.",
      });
    } finally {
      client.release();
    }
  },
);

router.put(
  "/:userId/toggle-status",
  verifyPermission("modify_users_status", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const { is_active } = req.body;

    if (is_active === undefined) {
      return res.status(400).json({
        success: false,
        message: "Missing payload parameter: is_active",
      });
    }

    const operatorId = req.user.id;

    // Prevent self-suspension suicide loop
    if (String(userId) === String(operatorId) && !is_active) {
      return res.status(403).json({
        success: false,
        message:
          "Self-protection guard active: You cannot suspend your own login account profile.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Verify the target exists
      const userCheck = await client.query(
        "SELECT full_name, is_active FROM public.super_admins WHERE id = $1",
        [userId],
      );
      if (userCheck.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message: "Target administrator record not found.",
        });
      }

      const targetUser = userCheck.rows[0];

      // Update active status mapping state
      await client.query(
        `UPDATE public.super_admins 
         SET is_active = $1, updated_at = CURRENT_TIMESTAMP 
         WHERE id = $2`,
        [is_active, userId],
      );

      // 🎯 IF SUSPENDING: Obliterate active cookie login sessions immediately
      if (!is_active) {
        await client.query(
          `DELETE FROM public.session 
           WHERE sess->'passport'->'user'->>'id' = $1`,
          [userId],
        );
      }

      // Log structural forensics trail footprint
      await createAuditLog(req, {
        action_type: is_active
          ? "ACTIVATE_USER_ACCOUNT"
          : "SUSPEND_USER_ACCOUNT",
        target_resource: "super_admins",
        target_id: userId,
        description: `Modified access permissions: Forcibly shifted account status for "${targetUser.full_name}" to [${is_active ? "ACTIVE" : "SUSPENDED"}].`,
        state_before: { is_active: targetUser.is_active },
        state_after: { is_active },
        log_type: "user",
      });

      await client.query("COMMIT");
      return res.json({
        success: true,
        message: `Account profile for ${targetUser.full_name} has been successfully ${is_active ? "activated" : "suspended and stripped of active sessions"}.`,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Status Toggle Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal transaction failure modifying status profiles.",
      });
    } finally {
      client.release();
    }
  },
);

// ─── DELETE: PERMANENTLY PURGE USER FROM CORE DATABASE ───
router.delete(
  "/:userId",
  verifyPermission("delete_user", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const operatorId = req.user.id;

    if (String(userId) === String(operatorId)) {
      return res.status(403).json({
        success: false,
        message:
          "Operation restricted. You cannot drop your own admin profile context.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Verify row exists and collect metadata for audit log prior to execution deletion
      const userCheck = await client.query(
        "SELECT full_name, email FROM public.super_admins WHERE id = $1",
        [userId],
      );
      if (userCheck.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message:
            "Target profile does not exist within the workspace database repository.",
        });
      }

      const targetUser = userCheck.rows[0];

      // 1. Purge all operational session mappings instantly
      await client.query(
        `DELETE FROM public.session 
         WHERE sess->'passport'->'user'->>'id' = $1`,
        [userId],
      );

      // 2. Hard delete account entry record
      await client.query("DELETE FROM public.super_admins WHERE id = $1", [
        userId,
      ]);

      // 3. Write final forensic audit tombstone signature
      await createAuditLog(req, {
        action_type: "PURGE_USER_ACCOUNT_RECORD",
        target_resource: "super_admins",
        target_id: userId,
        description: `CRITICAL HARD PURGE: Master Super Admin permanently deleted account vector profiling for "${targetUser.full_name}" (${targetUser.email}).`,
        state_before: {
          full_name: targetUser.full_name,
          email: targetUser.email,
        },
        state_after: null,
        log_type: "user",
      });

      await client.query("COMMIT");
      return res.json({
        success: true,
        message: `Administrator profile entry "${targetUser.full_name}" permanently wiped.`,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Hard Purge Transaction System Failure Matrix:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal server error executing hard transactional account erasure.",
      });
    } finally {
      client.release();
    }
  },
);

export default router;
