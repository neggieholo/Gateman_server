import express from "express";
import pool from "./db.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { isAuth, isSuperAdmin, hasPermission } from "./middlewares.js";
import { generateSecret, generateURI, verify } from "otplib";
import { verifyPermission, parseUserAgent } from "./middlewares.js";
import { createAuditLog } from "./helpers.js";
import { loadPoliciesIntoMemory, getCachedPolicies } from "./policyCache.js";
import {
  sendAdminWelcomeEmail,
  sendPasswordResetCode,
  sendRegistrationOTP,
} from "./emailService.js";
import geoip from "geoip-lite";

const router = express.Router();

router.use(isSuperAdmin);
router.use(isAuth);


router.get(
  "/network-status-matrices",
  verifyPermission("view_security_perimeter", "security_infrastructure"),
  async (req, res) => {
    try {
      const liveQuery = await pool.query(
        `SELECT 
        s.sess,
        a.id AS admin_id,
        a.full_name,
        a.email,
        CASE 
          WHEN s.sess->>'ip' IS NOT NULL THEN
            EXISTS (
              SELECT 1 FROM security_ip_rules r 
              WHERE r.ip_or_cidr::text = s.sess->>'ip' AND r.rule_type = 'ALLOW'
            )
          ELSE FALSE
        END as is_whitelisted
       FROM "session" s
       JOIN super_admins a ON (
         s.sess->'passport'->'user'->>'id' IS NOT NULL 
         AND (s.sess->'passport'->'user'->>'id')::uuid = a.id
       )
       WHERE s.expire > CURRENT_TIMESTAMP`,
      );

      const connections = liveQuery.rows.map((row) => {
        const sessionData =
          typeof row.sess === "string" ? JSON.parse(row.sess) : row.sess;
        const clientIp = sessionData.ip || "127.0.0.1";

        let calculatedLocation = "Unknown Location";

        // 🗺️ RESOLVING ROUTING SCENARIOS
        if (sessionData.coordinates && sessionData.coordinates.latitude) {
          // 🟢 CASE 1: Precise GPS Coordinates available
          const { latitude, longitude } = sessionData.coordinates;
          // Stringified so your frontend components can pass it cleanly to fetchReadableAddress()
          calculatedLocation = JSON.stringify({ latitude, longitude });
        } else if (clientIp === "127.0.0.1" || clientIp === "::1") {
          // 🔵 CASE 2: Dev Environment Loopback
          calculatedLocation = "Localhost Loopback";
        } else {
          // 🟡 CASE 3: DYNAMIC IP ANCHORING FALLBACK
          const geoLookup = geoip.lookup(clientIp);

          if (geoLookup) {
            const city = geoLookup.city || "Unknown City";
            const country = geoLookup.country || "Unknown Country";
            // 🎯 Append (Fallback) explicitly as requested
            calculatedLocation = `${city}, ${country} (Fallback)`;
          } else {
            calculatedLocation = "Remote Node (Fallback)";
          }
        }

        // console.log(
        //   `Admin ID: ${row.admin_id}, IP: ${clientIp}, Location: ${calculatedLocation}`,
        // );
        return {
          id: row.admin_id,
          name: row.full_name,
          email: row.email,
          ip: clientIp,
          device: sessionData.userAgent || "Unknown Device",
          location: calculatedLocation,
          isApproved: row.is_whitelisted,
        };
      });

      res.json({
        success: true,
        liveConnections: connections.filter((c) => c.isApproved === true),
        pendingRequests: connections.filter((c) => c.isApproved === false),
      });
    } catch (err) {
      console.error(
        "CRITICAL CRASH inside network-status-matrices query layer:",
        err.message,
      );
      res.status(500).json({
        success: false,
        message: "Internal server error sorting network vectors.",
      });
    }
  },
);

router.get(
  "/firewall-rules",
  verifyPermission("view_security_perimeter", "security_infrastructure"),
  async (req, res) => {
    try {
      // 🎯 QUERY: Get all custom rules ordered by the most recently added vectors
      const rulesQuery = await pool.query(
        `SELECT 
        s.id,
        s.ip_or_cidr AS network,
        s.rule_type AS type,
        s.label,
        s.created_by AS "addedById",
        sa.full_name AS "addedByName"
       FROM security_ip_rules s
       JOIN super_admins sa ON s.created_by = sa.id
       ORDER BY s.created_at DESC`,
      );

      // Return the rows directly to match your RuleNode[] frontend interface structure
      res.json({
        success: true,
        rules: rulesQuery.rows,
      });
    } catch (err) {
      console.error("Failed to compile firewall rules array ledger:", err);
      res.status(500).json({
        success: false,
        message: "Internal server error reading perimeter security tables.",
      });
    }
  },
);

// =========================================================================
// 🟢 1. APPROVE PENDING IP
// =========================================================================
router.post(
  "/approve-ip",
  verifyPermission("change_ip_status", "security_infrastructure"),
  async (req, res) => {
    const { adminId, ipAddress } = req.body;

    // Extracting details from the active passport auth middleware context
    const executorId = req.user?.id;
    const executorName = req.user?.full_name || "System Admin";

    if (!adminId || !ipAddress) {
      return res.status(400).json({
        success: false,
        message: "Missing administrative reference metadata attributes.",
      });
    }

    try {
      // 🔍 PRE-FETCH PIPELINE: Resolve target owner's name before database insertion
      const targetAdminQuery = await pool.query(
        `SELECT full_name FROM super_admins WHERE id = $1`,
        [adminId],
      );

      if (targetAdminQuery.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Target administrative user identity context not found in active registries.",
        });
      }

      const targetAdminName = targetAdminQuery.rows[0].full_name;

      // Inbound check if a rule structure already tracks this target parameter signature
      const checkExist = await pool.query(
        `SELECT * FROM security_ip_rules WHERE ip_or_cidr = $1`,
        [ipAddress],
      );

      let updatedOrCreatedRule;

      if (checkExist.rows.length > 0) {
        // Update existing record with refreshed properties and denormalized string states
        const updateRes = await pool.query(
          `UPDATE security_ip_rules 
         SET rule_type = 'ALLOW', 
             label = $1, 
             created_by = $2, 
             created_by_name = $3,
             permitted_by = $4, 
             permitted_by_name = $5,
             created_at = CURRENT_TIMESTAMP 
         WHERE ip_or_cidr = $6
         RETURNING *`,
          [
            `Authorized Perimeter Access IP`,
            adminId,
            targetAdminName,
            executorId,
            executorName,
            ipAddress,
          ],
        );
        updatedOrCreatedRule = updateRes.rows[0];
      } else {
        // Inbound record declaration for unique network node rule entry paths
        const insertRes = await pool.query(
          `INSERT INTO security_ip_rules (
          ip_or_cidr, 
          rule_type, 
          label, 
          created_by, 
          created_by_name, 
          permitted_by, 
          permitted_by_name
         ) VALUES ($1, 'ALLOW', $2, $3, $4, $5, $6)
         RETURNING *`,
          [
            ipAddress,
            `Authorized Perimeter Access IP`,
            adminId,
            targetAdminName,
            executorId,
            executorName,
          ],
        );
        // 🎯 FIXED: Assigned the returned row array data to our payload reference cleanly
        updatedOrCreatedRule = insertRes.rows[0];
      }

      // 📝 Post Operational Audit Pipeline Registry
      await createAuditLog(req, {
        log_type: "security",
        action_type: "PERIMETER_ALTERATION",
        target_resource: "security_ip_rules",
        target_id: updatedOrCreatedRule.id,
        description: `Whitelisted network node endpoint IP ${ipAddress} for Owner: ${targetAdminName} (ID: ${adminId}). Approved by: ${executorName} (ID: ${executorId})`,
        state_before: checkExist.rows[0] || null,
        state_after: updatedOrCreatedRule,
      });

      res.json({
        success: true,
        message:
          "Network authorization vector compiled and denormalized successfully.",
      });
    } catch (err) {
      console.error(
        "Perimeter gate whitelist authorization compilation failure:",
        err,
      );
      res.status(500).json({
        success: false,
        message: "Database layer exception configuring whitelist constraints.",
      });
    }
  },
);

// =========================================================================
// 🔴 2. TERMINATE LIVE SESSIONS & BLACKLIST TARGET IP
// =========================================================================
router.post(
  "/blacklist-ip",
  verifyPermission("change_ip_status", "security_infrastructure"),
  async (req, res) => {
    const { ipToBan, adminId } = req.body;
    console.log(
      "Received blacklist request for IP:",
      ipToBan,
      "with adminId:",
      adminId,
    );

    const executorId = req.user?.id;
    const executorName = req.user?.full_name || "System Admin";

    if (!ipToBan) {
      return res
        .status(400)
        .json({
          success: false,
          message:
            "Missing targeted node signature target parameter configuration.",
        });
    }

    try {
      // 1. Resolve targeted admin owner's name if an adminId was explicitly passed
      let targetAdminName = "No Linked Account";

      if (adminId) {
        const targetQuery = await pool.query(
          `SELECT full_name FROM super_admins WHERE id = $1`,
          [adminId],
        );
        if (targetQuery.rows.length > 0) {
          targetAdminName = targetQuery.rows[0].full_name;
        }
      }

      // 2. Inbound check if a rule structure already tracks this target parameters vector
      const checkExist = await pool.query(
        `SELECT * FROM security_ip_rules WHERE ip_or_cidr = $1`,
        [ipToBan],
      );

      let enforcedRule;

      if (checkExist.rows.length > 0) {
        const updateRes = await pool.query(
          `UPDATE security_ip_rules 
         SET rule_type = 'DENY', 
             label = $1, 
             created_by = $2, 
             created_by_name = $3,
             permitted_by = $4,
             permitted_by_name = $5,
             created_at = CURRENT_TIMESTAMP 
         WHERE ip_or_cidr = $6
         RETURNING *`,
          [
            `Revoked and Permanently Blacklisted`,
            adminId || null, // Tracks the owner/compromised target identity
            targetAdminName,
            executorId, // Tracks the enforcer executing the post action
            executorName,
            ipToBan,
          ],
        );
        enforcedRule = updateRes.rows[0];
      } else {
        const insertRes = await pool.query(
          `INSERT INTO security_ip_rules (
          ip_or_cidr, 
          rule_type, 
          label, 
          created_by, 
          created_by_name, 
          permitted_by, 
          permitted_by_name
         ) VALUES ($1, 'DENY', $2, $3, $4, $5, $6)
         RETURNING *`,
          [
            ipToBan,
            `Revoked and Permanently Blacklisted`,
            adminId || null,
            targetAdminName,
            executorId,
            executorName,
          ],
        );
        enforcedRule = insertRes.rows[0];
      }

      let purgeSessions;
      if (adminId) {
        // Case A: We have a specific admin target. Kill sessions matching their IP OR their Account ID
        purgeSessions = await pool.query(
          `DELETE FROM "session" 
     WHERE sess->>'ip' = $1 
        OR (sess->'passport'->'user'->>'id' IS NOT NULL AND (sess->'passport'->'user'->>'id')::uuid = $2)
     RETURNING sid`,
          [ipToBan, adminId],
        );
      } else {
        // Case B: Network-level block only (No admin account linked). Evict strictly by IP footprint
        purgeSessions = await pool.query(
          `DELETE FROM "session" 
     WHERE sess->>'ip' = $1
     RETURNING sid`,
          [ipToBan],
        );
      }

      console.log(
        `🔥 Security enforcement severed ${purgeSessions.rowCount} active session connection hooks for IP: ${ipToBan}`,
      );

      // 📝 Post Operational Audit Pipeline Registry
      await createAuditLog(req, {
        log_type: "security",
        action_type: "SECURITY_PERIMETER_REVOCATION",
        target_resource: "security_ip_rules",
        target_id: enforcedRule.id,
        description: `Severed and Blacklisted IP ${ipToBan} linked to Admin: ${targetAdminName}. ${purgeSessions.rowCount} active connection handshakes purged by ${executorName}.`,
        state_before: checkExist.rows[0] || null,
        state_after: enforcedRule,
      });

      res.json({
        success: true,
        message:
          "Handshake severed cleanly. Enforcement block rules synchronized globally.",
      });
    } catch (err) {
      console.error("Perimeter gate blacklisting runtime exception:", err);
      res
        .status(500)
        .json({
          success: false,
          message:
            "Database infrastructure exception deploying restriction parameters.",
        });
    }
  },
);

// =========================================================================
// ➕ 3. ADD MANUAL FIREWALL RULE VECTOR
// =========================================================================
router.post(
  "/add-manual-rule",
  verifyPermission("add_firewall_rule", "security_infrastructure"),
  async (req, res) => {
    const { ipOrCidr, ruleType, label } = req.body;

    // Extracting execution keys cleanly from incoming passports
    const executorId = req.user?.id;
    const executorName = req.user?.full_name || "System Admin";

    if (!ipOrCidr || !ruleType) {
      return res.status(400).json({
        success: false,
        message: "Missing required core rule schema parameters mapping nodes.",
      });
    }

    try {
      const checkExist = await pool.query(
        `SELECT * FROM security_ip_rules WHERE ip_or_cidr = $1`,
        [ipOrCidr.trim()],
      );

      let manualRule;

      if (checkExist.rows.length > 0) {
        const updateRes = await pool.query(
          `UPDATE security_ip_rules 
         SET rule_type = $1, 
             label = $2, 
             created_by = $3, 
             created_by_name = $4,
             permitted_by = $5,
             permitted_by_name = $6,
             created_at = CURRENT_TIMESTAMP 
         WHERE ip_or_cidr = $7
         RETURNING *`,
          [
            ruleType,
            label || "Manual Static Assignment",
            executorId,
            executorName,
            executorId,
            executorName,
            ipOrCidr.trim(),
          ],
        );
        manualRule = updateRes.rows[0];
      } else {
        const insertRes = await pool.query(
          `INSERT INTO security_ip_rules (
          ip_or_cidr, 
          rule_type, 
          label, 
          created_by, 
          created_by_name, 
          permitted_by, 
          permitted_by_name
         ) VALUES ($1, $2, $3, $4, $5, $6, $7)
         RETURNING *`,
          [
            ipOrCidr.trim(),
            ruleType,
            label || "Manual Static Assignment",
            executorId,
            executorName,
            executorId,
            executorName,
          ],
        );
        manualRule = insertRes.rows[0];
      }

      // If it's a manual blacklist rule assignment, clean out running sessions from that IP/CIDR target too!
      if (ruleType === "DENY") {
        await pool.query(`DELETE FROM "session" WHERE sess->>'ip' = $1`, [
          ipOrCidr.trim(),
        ]);
      }

      // 📝 Post Operational Audit Pipeline Registry (Matching exact signature structure without severity)
      await createAuditLog(req, {
        log_type: "security",
        action_type: "SECURITY_MANUAL_RULE_INJECTION",
        target_resource: "security_ip_rules",
        target_id: manualRule.id,
        description: `Compiled static rule context [${ruleType}] array mapping for ${ipOrCidr} by ${executorName}`,
        state_before: checkExist.rows[0] || null,
        state_after: manualRule,
      });

      res.json({
        success: true,
        message: "Static guard policy deployed cleanly.",
      });
    } catch (err) {
      console.error("Static rule deployment exception handling parsing:", err);
      res.status(500).json({
        success: false,
        message: "Failed to compile manual static guard configurations.",
      });
    }
  },
);

// =========================================================================
// 🗑️ 4. PURGE FIREWALL RULE RECORD BY UUID IDENTIFIER
// =========================================================================
router.delete(
  "/firewall-rules/:ruleId",
  verifyPermission("delete_firewall_rule", "security_infrastructure"),
  async (req, res) => {
    const { ruleId } = req.params;

    if (!ruleId) {
      return res.status(400).json({
        success: false,
        message: "Missing target unique rule reference key matrix identifier.",
      });
    }

    try {
      const ruleDetails = await pool.query(
        `SELECT ip_or_cidr, rule_type FROM security_ip_rules WHERE id = $1`,
        [ruleId],
      );

      if (ruleDetails.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Target constraint parameters row entry not found in active data schemas.",
        });
      }

      const { ip_or_cidr, rule_type } = ruleDetails.rows[0];

      await pool.query(`DELETE FROM security_ip_rules WHERE id = $1`, [ruleId]);

      await createAuditLog(req, {
        log_type: "security",
        action_type: "SECURITY_RULE_DELETION",
        target_resource: "security_ip_rules",
        target_id: ruleId,
        description: `Purged restriction parameter rule layout configuration targeting [${rule_type}] ${ip_or_cidr}`,
        state_before: ruleDetails.rows[0] || null,
        state_after: null,
      });

      res.json({
        success: true,
        message:
          "Rule constraints dropped cleanly from core parsing schema map matrix rows.",
      });
    } catch (err) {
      console.error("Exception handling drop directive execution paths:", err);
      res.status(500).json({
        success: false,
        message:
          "Internal runtime failure executing firewall database row dropping script.",
      });
    }
  },
);


router.get(
  "/system-policies",
  verifyPermission("edit_system_policies", "security_infrastructure"),
  async (req, res) => {
    try {
      const policies = await getCachedPolicies(pool);

      res.json({
        success: true,
        policies: {
          sessionTimeoutMinutes: policies.session_timeout_minutes,
          rememberMeDurationDays: policies.remember_me_duration_days,
          absoluteTimeoutHours: policies.absolute_timeout_hours,
          pwdMinLength: policies.pwd_min_length,
          pwdRequireUppercase: policies.pwd_require_uppercase,
          pwdRequireLowercase: policies.pwd_require_lowercase,
          pwdRequireNumbers: policies.pwd_require_numbers,
          pwdRequireSymbols: policies.pwd_require_symbols,
          pwdPreventReuseCount: policies.pwd_prevent_reuse_count,
          pwdExpiryDays: policies.pwd_expiry_days,
          maxLoginAttemptsBeforeLockout:
            policies.max_login_attempts_before_lockout,
          lockoutDurationMinutes: policies.lockout_duration_minutes,
          requireMfaForSubaccounts: policies.require_mfa_for_subaccounts,
          enforceActionAcceptanceBeforeLogin:
            policies.enforce_action_acceptance_before_login,
          updatedAt: policies.updated_at,
        },
      });
    } catch (err) {
      console.error("Failed to retrieve system policy matrices:", err);
      res
        .status(500)
        .json({
          success: false,
          message: "Internal server policy resolution error.",
        });
    }
  },
);

/**
 * 💾 POST: Update Global System Policies
 */
router.post(
  "/system-policies/update",
  verifyPermission("edit_system_policies", "security_infrastructure"),
  async (req, res) => {
    const {
      sessionTimeoutMinutes,
      rememberMeDurationDays,
      absoluteTimeoutHours,
      pwdMinLength,
      pwdRequireUppercase,
      pwdRequireLowercase,
      pwdRequireNumbers,
      pwdRequireSymbols,
      pwdPreventReuseCount,
      pwdExpiryDays,
      maxLoginAttemptsBeforeLockout,
      lockoutDurationMinutes,
      requireMfaForSubaccounts,
      enforceActionAcceptanceBeforeLogin,
    } = req.body;

    const policies = await getCachedPolicies(pool);

    try {
      // Write parameters cleanly into our single-row PostgreSQL configuration table
      await pool.query(
        `UPDATE system_policies 
         SET session_timeout_minutes = $1, 
             remember_me_duration_days = $2,
             absolute_timeout_hours = $3,
             pwd_min_length = $4, 
             pwd_require_uppercase = $5,
             pwd_require_lowercase = $6,
             pwd_require_numbers = $7,
             pwd_require_symbols = $8,
             pwd_prevent_reuse_count = $9,
             pwd_expiry_days = $10,
             max_login_attempts_before_lockout = $11,
             lockout_duration_minutes = $12,
             require_mfa_for_subaccounts = $13,
             enforce_action_acceptance_before_login = $14,
             updated_at = CURRENT_TIMESTAMP
         WHERE id = 1`,
        [
          sessionTimeoutMinutes,
          rememberMeDurationDays,
          absoluteTimeoutHours,
          pwdMinLength,
          pwdRequireUppercase,
          pwdRequireLowercase,
          pwdRequireNumbers,
          pwdRequireSymbols,
          pwdPreventReuseCount,
          pwdExpiryDays,
          maxLoginAttemptsBeforeLockout,
          lockoutDurationMinutes,
          requireMfaForSubaccounts,
          enforceActionAcceptanceBeforeLogin,
        ],
      );

      await loadPoliciesIntoMemory(pool);
      const updatedPolicies = await loadPoliciesIntoMemory(pool);

      await createAuditLog(req, {
        log_type: "security",
        action_type: "SECURITY_SYSTEM_POLICY_UPDATE",
        target_resource: "security_policies",
        target_id: "1",
        description: 'Global system policy matrices updated',
        state_before: policies,
        state_after: updatedPolicies,
      });
      console.log(
        "⚡ RAM Policy Cache refreshed cleanly in app memory server instance.",
      );

      res.json({
        success: true,
        message: "Policies updated globally and cache synchronized instantly.",
      });
    } catch (err) {
      console.error(
        "Database tracking fault updating policy schema mapping:",
        err,
      );
      res
        .status(500)
        .json({ success: false, message: "Database update error." });
    }
  },
);

export default router;
