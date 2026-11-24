import express from "express";
import pool from "./db.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
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
router.use(isSuperAdmin);
router.use(isAuth);

router.get(
  "/all",
  verifyPermission("view_estate_security", "estates_management"),
  async (req, res) => {
    try {
      const result = await pool.query(
        `SELECT 
        id, name, email, phone, estate_id, is_on_duty, 
        last_checkin, last_checkout, created_at, role,
        checkin_location, checkout_location, first_login, avatar,
        id_type, id_front_url, id_back_url, last_known_location,
        last_location_time, biometric_login, password_changed, status,
        last_activity_at
    FROM security_users
    ORDER BY created_at DESC`,
      );

      return res.status(200).json({
        success: true,
        securityUsers: result.rows,
      });
    } catch (err) {
      console.error(
        "Database query error on security users ledger pipeline:",
        err,
      );
      return res.status(500).json({
        success: false,
        message:
          "Internal pipeline engine error loading security guard registry maps.",
      });
    }
  },
);

router.get("/:estateId/all", verifyPermission("view_estate_security", "estates_management"), async (req, res) => {
  const { estateId } = req.params;

  try {
    const result = await pool.query(
      `SELECT 
        id, name, email, phone, estate_id, is_on_duty, 
        last_checkin, last_checkout, created_at, role,
        checkin_location, checkout_location, first_login, avatar,
        id_type, id_front_url, id_back_url, last_known_location,
        last_location_time, biometric_login, password_changed, status,
        last_activity_at
    FROM security_users
    WHERE estate_id = $1
    ORDER BY created_at DESC`,
      [estateId],
    );

    return res.status(200).json({
      success: true,
      securityUsers: result.rows,
    });
  } catch (err) {
    console.error(
      "Database query error on security users ledger pipeline:",
      err,
    );
    return res.status(500).json({
      success: false,
      message:
        "Internal pipeline engine error loading security guard registry maps.",
    });
  }
});

router.put("/:securityId/status", verifyPermission("modify_estate_guard_status", "estates_management"), async (req, res) => {
  const { securityId } = req.params;
  const { targetStatus } = req.body;

  if (!["ACTIVE", "SUSPENDED"].includes(targetStatus)) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid status type specified." });
  }

  try {
    const result = await pool.query(
      `UPDATE security_users 
       SET status = $1 
       WHERE id = $2
       RETURNING id, name, status`,
      [targetStatus, securityId],
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Security user record not found.",
      });
    }

    return res.status(200).json({
      success: true,
      message: `Account status updated to ${targetStatus} globally.`,
      securityUser: result.rows[0],
    });
  } catch (err) {
    console.error("Superadmin status update exception:", err);
    return res.status(500).json({
      success: false,
      message: "Internal pipeline error executing status change.",
    });
  }
});

router.delete(
  "/:securityId",
  verifyPermission("delete_estate_security_account", "estates_management"),
  async (req, res) => {
    const { securityId } = req.params;

    try {
      const result = await pool.query(
        `DELETE FROM security_users 
       WHERE id = $1
       RETURNING id, name`,
        [securityId],
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Security user record not found.",
        });
      }

      return res.status(200).json({
        success: true,
        message: `Account node for ${result.rows[0].name} has been globally purged from the GateMan system database.`,
      });
    } catch (err) {
      console.error("Superadmin global deletion engine exception:", err);
      return res.status(500).json({
        success: false,
        message: "Database engine error occurred during global profile purge.",
      });
    }
  },
);

export default router;
