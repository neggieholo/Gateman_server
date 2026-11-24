import express from "express";
import pool from "./db.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { createAppAuditLog } from "./helpers.js";
import {
  isAuth,
  ensureAdmin,
  verifyPermission,
  parseUserAgent,
  getClientIp,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import { generateSecret, generateURI, verify } from "otplib";
import {
  sendAdminWelcomeEmail,
} from "./emailService.js";
import { getCachedPolicies } from "./policyCache.js";

const router = express.Router();

router.post("/verify-login-otp", async (req, res, next) => {
  // 1. Destructure rememberMe from the inbound request payload body
  const { otp, metadata, target, type, rememberMe, coordinates } = req.body;

  try {
    const normalizedTarget = target.trim().toLowerCase();

    // Fetch full admin details to process login parameters
    const dbQuery = await pool.query(
      "SELECT * FROM estate_admin_users WHERE LOWER(email) = $1",
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
        "UPDATE estate_admin_users SET email_verified = true WHERE id = $1",
        [user.id],
      );

      user.email_verified = true;
    } else if (type === "totp") {
      console.log("TOTP verificaton commencing...");
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
        "UPDATE estate_admin_users SET is_first_login = false WHERE id = $1",
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
        "UPDATE estate_admin_users SET last_login = NOW() WHERE id = $1",
        [user.id],
      );

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        const { password, mfa_secret, backup_codes, ...safeUser } = user;
        return res.json({
          success: true,
          user: { ...safeUser, is_first_login: clientIsFirstLogin },
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

router.use(isAuth);
router.use(ensureAdmin);

router.post("/mfa/setup", async (req, res) => {
  try {
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
      // await pool.query(
      //   `UPDATE estate_admin_users
      //    SET mfa_enabled = true,
      //        mfa_type = 'TOTP',
      //        mfa_secret = $1
      //    WHERE id = $2`,
      //   [secret, req.user.id],
      // );

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

// ─── NEW: FETCH ALL GRANULAR SYSTEM PERMISSIONS ───
router.get(
  "/system-permissions",
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    console.log(
      "Fetching system permissions for estate admin user settings...",
    );
    try {
      const result = await pool.query(
        `SELECT id, name, parent_permission FROM estate_admin_permissions 
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

router.get(
  "/custom-roles/:estate_id",
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    const { estate_id } = req.params;
    try {
      const result = await pool.query(
        `SELECT id, role_name, description, permission_ids 
       FROM estate_custom_roles
       WHERE estate_id = $1 
       ORDER BY role_name ASC`,
        [estate_id],
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
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    const { role_name, description, permission_ids, estate_id } = req.body;

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
        "SELECT id FROM estate_custom_roles WHERE LOWER(role_name) = LOWER($1)",
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
      INSERT INTO estate_custom_roles (role_name, description, permission_ids, estate_id)
      VALUES ($1, $2, $3::VARCHAR(50)[], $4)
      RETURNING id, role_name, description, permission_ids;
    `;

      const result = await pool.query(insertQuery, [
        cleanName,
        description || null,
        permission_ids,
        estate_id,
      ]);

      const createdRole = result.rows[0];

      await createAppAuditLog(req, {
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
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("add_user", "users_management"),
  async (req, res) => {
    const {
      name,
      email,
      phone_number,
      require_password_change,
      permissions,
      estate_id,
    } = req.body;

    if (!estate_id || !name || !email || !Array.isArray(permissions)) {
      return res.status(400).json({
        success: false,
        message:
          "Missing core operational identification parameters or authorization arrays.",
      });
    }

    try {
      const cleanEmail = email.trim().toLowerCase();

      // 🔐 Check existing email
      const checkExist = await pool.query(
        "SELECT id FROM estate_admin_users WHERE LOWER(email) = $1",
        [cleanEmail],
      );
      if (checkExist.rows.length > 0) {
        return res.status(400).json({
          success: false,
          message:
            "An administrative profile with this email address already exists.",
        });
      }

      // Check existing phone number if provided
      if (phone_number) {
        const checkPhoneExist = await pool.query(
          "SELECT id FROM estate_admin_users WHERE LOWER(phone_number) = $1",
          [phone_number.trim()],
        );
        if (checkPhoneExist.rows.length > 0) {
          return res.status(400).json({
            success: false,
            message:
              "An administrative profile with this phone number already exists.",
          });
        }
      }

      // 🔑 Generate secure password parts internally
      const emailPasswordPart = crypto.randomBytes(3).toString("hex");
      const smsPasswordPart = "gate";
      const fullCombinedPassword = emailPasswordPart + smsPasswordPart;

      const passwordHash = await bcrypt.hash(fullCombinedPassword, 10);
      const insertQuery = `
        INSERT INTO estate_admin_users (
          name, 
          email, 
          password, 
          estate_ids, 
          phone_number, 
          must_change_password, 
          permissions, 
          is_first_login
        ) VALUES (
          $1, 
          $2, 
          $3, 
          ARRAY[$4]::uuid[], -- Wraps the incoming estate_id parameter into an array
          $5, 
          $6, 
          $7::VARCHAR(50)[], 
          true
        )
        RETURNING 
          id, name, email, phone_number, 
          must_change_password, permissions, is_first_login,
          email_verified, phone_verified, created_at;
      `;

      const result = await pool.query(insertQuery, [
        name.trim(),
        cleanEmail,
        passwordHash,
        estate_id,
        phone_number ? phone_number.trim() : null,
        require_password_change ?? true,
        permissions,
      ]);

      const createdAdmin = result.rows[0];

      // 📝 Commit audit log
      await createAppAuditLog(req, {
        action_type: "CREATE_ADMIN",
        target_resource: "estate_admin_users",
        target_id: createdAdmin.id,
        description: `Successfully built managed admin profile for ${createdAdmin.name} (${cleanEmail}).`,
        state_before: null,
        state_after: createdAdmin,
        log_type: "user",
      });

      // ✉️ Dispatch credentials based on presence of phone number
      if (phone_number) {
        try {
          await sendAdminWelcomeEmail(
            cleanEmail,
            name.trim(),
            emailPasswordPart,
            require_password_change ?? true,
            true,
          );
          console.log(
            `Admin email credential part dispatched to ${cleanEmail}`,
          );
        } catch (mailErr) {
          console.error("⚠️ Background email dispatch failed:", mailErr);
        }

        console.log(
          `[TEST MODE SMS TOKEN SIMULATION] Phone: ${phone_number} | Token: ${smsPasswordPart}`,
        );
      } else {
        try {
          await sendAdminWelcomeEmail(
            cleanEmail,
            name.trim(),
            fullCombinedPassword,
            require_password_change ?? true,
            false,
          );
          console.log(
            `Full admin email credentials dispatched to ${cleanEmail}`,
          );
        } catch (mailErr) {
          console.error("⚠️ Background email dispatch failed:", mailErr);
        }
      }

      return res.status(201).json({
        success: true,
        message: "Administrative profile created successfully.",
        admin: createdAdmin,
      });
    } catch (err) {
      console.error("Onboard Admin Workspace Error Exception Handler:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error creating administrative profile.",
      });
    }
  },
);

router.get(
  "/admins/:estate_id",
  authorizeEstate,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("view_users", "users_management"),
  async (req, res) => {
    try {
      const estateId = req.params.estate_id;
      const userPermissions = req.user?.permissions || [];
      const hasAllAccess = userPermissions.includes("all-access");

      let queryStr = `
        SELECT 
          id, 
          name, 
          email, 
          phone_number, 
          mfa_enabled, 
          mfa_type, 
          sub_account, 
          permissions,
          phone_verified,
          email_verified,
          is_active,
          avatar,
          created_at
        FROM estate_admin_users
        WHERE id != $1 AND name IS NOT NULL AND $2 = ANY(estate_ids)
      `;
      const queryParams = [req.user.id, estateId];

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
        users: result.rows,
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
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("modify_user_permissions", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const { permissions, estate_id: estateId } = req.body;

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
        SELECT id, name, email, permissions 
        FROM estate_admin_users 
        WHERE id = $1 AND estate_id = $2
      `;

      const snapshotResult = await client.query(snapshotQuery, [
        userId,
        estateId,
      ]);

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
        UPDATE estate_admin_users 
        SET 
          permissions = $1::VARCHAR(50)[]
        WHERE id = $2 AND estate_id = $3
        RETURNING id, name, email, permissions;
      `;

      const result = await client.query(updateQuery, [
        permissions,
        userId,
        estateId,
      ]);
      const updatedAdmin = result.rows[0];

      // 🎯 Step 3: Write structural forensic security trail log footprint
      await createAppAuditLog(req, {
        action_type: "MUTATE_USER_PERMISSIONS",
        target_resource: "estate_admin_users ",
        target_id: updatedAdmin.id,
        description: `Reconfigured granular feature access authorization matrix for admin: "${updatedAdmin.name}" (${updatedAdmin.email})`,
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
          name: updatedAdmin.name,
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

// ─── POST: ADMINISTRATIVE EXPLICIT PASSWORD OVERRIDE BYPASS ───
router.post(
  "/:subAccountId/override-password",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("modify_users_pass", "users_management"),
  async (req, res) => {
    const { subAccountId } = req.params;
    const { newPassword, estate_id } = req.body;

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

      const targetQuery = `SELECT id, name, email FROM estate_admin_users WHERE id = $1 AND estate_id = $2`;
      const targetResult = await client.query(targetQuery, [
        subAccountId,
        estate_id,
      ]);

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
        UPDATE estate_admin_users
        SET 
          password = $1,
          must_change_password = true, 
          is_first_login = true,
          reset_token = NULL,
          reset_token_expiry = NULL
        WHERE id = $2
      `;
      await client.query(updateQuery, [hashedPassword, subAccountId]);

      // Write forensic trail log record footprint
      await createAppAuditLog(req, {
        action_type: "FORCE_RESET_USER_PASSWORD",
        target_resource: "estate_admin_users",
        target_id: subAccountId,
        description: `Root Admin explicitly updated password parameters for managed sub-account entry: "${subAccount.name}" (${subAccount.email}) and enforced renewal sequence flags.`,
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
        message: `Credentials reconfigured successfully for ${subAccount.name}. User will be prompted to renew password on next workspace login initialization.`,
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
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("modify_users_mfa", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const { mfa_enabled, estate_id } = req.body;
    console.log("Received MFA policy update request:", { mfa_enabled });

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
        "SELECT id, name, email, mfa_enabled FROM estate_admin_users WHERE id = $1 AND estate_id = $2",
        [userId, estate_id],
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

      const updateQuery = `
        UPDATE estate_admin_users
        SET 
          mfa_enabled = $1
        WHERE id = $2
        RETURNING id, name, email, mfa_enabled, mfa_type;
      `;
      const result = await client.query(updateQuery, [mfa_enabled, userId]);
      const updatedAdmin = result.rows[0];

      await createAppAuditLog(req, {
        action_type: mfa_enabled ? "ENFORCE_USER_MFA" : "DISABLE_USER_MFA",
        target_resource: "estate_admin_users",
        target_id: userId,
        description: `Modified authentication profile: Forcibly toggled MFA restriction state for administrator node "${targetUser.name}" to [${mfa_enabled ? "ENABLED" : "DISABLED"}]. Underlying registration method preserved.`,
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
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("modify_users_status", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const { is_active, estate_id } = req.body;

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
        "SELECT name, is_active FROM estate_admin_users WHERE id = $1 AND estate_id = $2",
        [userId, estate_id],
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
        `UPDATE estate_admin_users 
         SET is_active = $1 
         WHERE id = $2`,
        [is_active, userId],
      );

      // 🎯 IF SUSPENDING: Obliterate active cookie login sessions immediately
      if (!is_active) {
        await client.query(
          `DELETE FROM session 
           WHERE sess->'passport'->'user'->>'id' = $1`,
          [userId],
        );
      }

      // Log structural forensics trail footprint
      await createAppAuditLog(req, {
        action_type: is_active
          ? "ACTIVATE_USER_ACCOUNT"
          : "SUSPEND_USER_ACCOUNT",
        target_resource: "estate_admin_users",
        target_id: userId,
        description: `Modified access permissions: Forcibly shifted account status for "${targetUser.name}" to [${is_active ? "ACTIVE" : "SUSPENDED"}].`,
        state_before: { is_active: targetUser.is_active },
        state_after: { is_active },
        log_type: "user",
      });

      await client.query("COMMIT");
      return res.json({
        success: true,
        message: `Account profile for ${targetUser.name} has been successfully ${is_active ? "activated" : "suspended and stripped of active sessions"}.`,
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
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("delete_user", "users_management"),
  async (req, res) => {
    const { userId } = req.params;
    const estateId = req.query.estate_id;
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
        "SELECT name, email FROM estate_admin_users WHERE id = $1 AND estate_id = $2",
        [userId, estateId],
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
        `DELETE FROM session 
         WHERE sess->'passport'->'user'->>'id' = $1`,
        [userId],
      );

      // 2. Hard delete account entry record
      await client.query(
        "DELETE FROM estate_admin_users WHERE id = $1 AND estate_id = $2",
        [userId, estateId],
      );

      // 3. Write final forensic audit tombstone signature
      await createAppAuditLog(req, {
        action_type: "PURGE_USER_ACCOUNT_RECORD",
        target_resource: "estate_admin_users",
        target_id: userId,
        description: `CRITICAL HARD PURGE: Master Super Admin permanently deleted account vector profiling for "${targetUser.name}" (${targetUser.email}).`,
        state_before: {
          name: targetUser.name,
          email: targetUser.email,
        },
        state_after: null,
        log_type: "user",
      });

      await client.query("COMMIT");
      return res.json({
        success: true,
        message: `Administrator profile entry "${targetUser.name}" permanently wiped.`,
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

// ─── FETCH ALL FORENSIC USER LOGS WITH FILTER SLICES ───
router.post(
  "/user-logs",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission(
    ["view_user_logs", "view_resident_logs", "view_security_logs"],
    "users_management",
  ),
  async (req, res) => {
    try {
      const { role, estate_id: estateId } = req.body;

      const queryParams = [estateId, role];

      let queryStr = `
        SELECT 
          id, user_id, user_name, user_email, 
          action_type, target_resource, target_id, 
          description, state_before, state_after, 
          ip_address, user_agent, created_at
        FROM app_logs
        WHERE estate_id = $1 AND user_role = $2
      `;

      queryStr += ` ORDER BY created_at DESC`;

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

export default router;
