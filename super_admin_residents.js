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


router.get("/all", verifyPermission("view_estate_residents", "estates_management"), async (req, res) => {
  try {
    const estateQuery = `SELECT id, name FROM estates;`;
    const estateRes = await pool.query(estateQuery);

    // 2. Fetch all tenants belonging to this specific dashboard estate screen context
    const residentsQuery = `
      SELECT 
        id, estate_ids, name, email, parent_account_id, sub_users, avatar, phone, created_at, status, locations, biometric_login, last_activity_at 
      FROM tenant_users 
      ORDER BY name ASC;
    `;
    const residentsRes = await pool.query(residentsQuery);

    return res.json({
      success: true,
      estatesList: estateRes.rows,
      residents: residentsRes.rows,
    });
  } catch (err) {
    console.error("Failed to pull estate residents aggregation vector:", err);
    return res.status(500).json({
      success: false,
      message: "Infrastructure error collecting tenant registry accounts.",
    });
  }
});

router.get("/:estateId/all", verifyPermission("view_estate_residents", "estates_management"), async (req, res) => {
  try {
    const { estateId } = req.params;

    // 1. Fetch a global list of all estates to build an ID-to-Name map on the frontend
    const estateQuery = `SELECT id, name FROM estates;`;
    const estateRes = await pool.query(estateQuery);

    // 2. Fetch all tenants belonging to this specific dashboard estate screen context
    const residentsQuery = `
      SELECT 
        id, estate_ids, name, email, parent_account_id, sub_users, avatar, phone, created_at, status, locations, biometric_login, last_activity_at 
      FROM tenant_users 
      WHERE $1 = ANY(estate_ids)
      ORDER BY name ASC;
    `;
    const residentsRes = await pool.query(residentsQuery, [estateId]);

    return res.json({
      success: true,
      estatesList: estateRes.rows,
      residents: residentsRes.rows,
    });
  } catch (err) {
    console.error("Failed to pull estate residents aggregation vector:", err);
    return res.status(500).json({
      success: false,
      message: "Infrastructure error collecting tenant registry accounts.",
    });
  }
});

router.put("/:residentId/status", verifyPermission("modify_estate_resident_status", "estates_management"), async (req, res) => {
  const { residentId } = req.params;
  const { targetStatus } = req.body;

  if (!["ACTIVE", "SUSPENDED"].includes(targetStatus)) {
    return res
      .status(400)
      .json({ success: false, message: "Invalid status type specified." });
  }

  try {
    const result = await pool.query(
      `UPDATE tenant_users 
       SET status = $1 
       WHERE id = $2
       RETURNING id, name, status`,
      [targetStatus, residentId],
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({
          success: false,
          message: "Resident account record not found.",
        });
    }

    return res.status(200).json({
      success: true,
      message: `Account status updated to ${targetStatus} globally.`,
      resident: result.rows[0],
    });
  } catch (err) {
    console.error("Superadmin status update exception:", err);
    return res
      .status(500)
      .json({
        success: false,
        message: "Internal pipeline error executing status change.",
      });
  }
});

router.delete("/:residentId", verifyPermission("delete_estate_resident_account", "estates_management"), async (req, res) => {
  const { residentId } = req.params;

  try {
    const result = await pool.query(
      `DELETE FROM tenant_users 
       WHERE id = $1
       RETURNING id, name`,
      [residentId],
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({
          success: false,
          message: "Resident profile target not found in master registry.",
        });
    }

    return res.status(200).json({
      success: true,
      message: `Account node for ${result.rows[0].name} has been globally purged from the GateMan system database.`,
    });
  } catch (err) {
    console.error("Superadmin global deletion engine exception:", err);
    return res
      .status(500)
      .json({
        success: false,
        message: "Database engine error occurred during global profile purge.",
      });
  }
});


export default router;