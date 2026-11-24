import express from "express";
import multer from "multer";
import pool from "./db.js";
import {
  ensureAdmin,
  isAuth,
  authorizeEstate,
  verifyPermission,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import { sendRegistrationOTP } from "./emailService.js";
import crypto from "crypto";
import bcrypt from "bcrypt";
import { io } from "./server.js";
import { sendPushNotification } from "./invitations.js";
import { createAppAuditLog, uploadToS3Direct } from "./helpers.js";
import {
  sendTenantWelcomeEmail,
  sendTenantApprovalEmail,
} from "./emailService.js";
import { verify } from "otplib";

const router = express.Router();

router.post("/verify-otp-only", async (req, res) => {
  const { otp, metadata, target, type } = req.body;
  console.log("Verifying OTP with metadata:", metadata, "and target:", target);
  try {
    // 1. Normalize the target (Remove spaces and lowercase email)
    let normalizedTarget;
    if (type === "email") {
      normalizedTarget = target.trim().toLowerCase();
    } else {
      normalizedTarget = target.trim();
    }
    console.log("Normalized Target for OTP Verification:", normalizedTarget);

    const [hash, expires] = metadata.split(".");

    if (Date.now() > parseInt(expires)) {
      return res.status(400).json({ error: "OTP expired. Please resend." });
    }

    // 3. Re-create the hash using the EXACT same format as the send route
    const data = `${normalizedTarget}.${otp}.${expires}`;
    console.log("Data for OTP Hash Verification:", data);
    const verifyHash = crypto
      .createHmac(
        "sha256",
        "0022c30a40599aae79fb6a7ea31bf742a11b9618663521f0dea2f94954de2dbb",
      )
      .update(data)
      .digest("hex");
    console.log("Recreated Hash for Verification:", verifyHash);

    if (verifyHash !== hash) {
      return res.json({ success: false, message: "Invalid OTP code." });
    }

    const isSuperAdmin = req.user && req.user.role === "SUPER_ADMIN";

    if (isSuperAdmin && type === "email") {
      await pool.query(
        `UPDATE super_admins SET email_verified = TRUE WHERE id = $1`,
        [req.user.id],
      );

      req.user.email_verified = true;
    }

    if (isSuperAdmin && type === "phone") {
      await pool.query(
        `UPDATE super_admins SET phone_verified = TRUE WHERE id = $1`,
        [req.user.id],
      );

      req.user.phone_verified = true;
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Verification Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.use(isAuth);

router.post("/verify-totp", ensureAdmin, async (req, res, next) => {
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

router.get("/my-request", async (req, res) => {
  const tempUserId = req.user.id;
  console.log(`Fetching my request for user: ${tempUserId}`);

  try {
    const activeRes = await pool.query(
      `SELECT jr.*, e.name as estate_name 
       FROM join_requests jr
       JOIN estates e ON jr.estate_id = e.id
       WHERE jr.temp_tenant_id = $1 AND jr.status = 'PENDING'`,
      [tempUserId],
    );

    const userRes = await pool.query(
      "SELECT rejection_message, is_read FROM temp_tenant_users WHERE id = $1",
      [tempUserId],
    );

    res.json({
      success: true,
      activeRequest: activeRes.rows[0] || null,
      feedback: userRes.rows[0]?.rejection_message || null,
      isRead: userRes.rows[0]?.is_read ?? false,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});

// -------------------- Dismiss/Delete Notification --------------------
router.delete("/notification/dismiss", async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const userId = req.user.id;
  const isPermanentTenant = !!req.user.estate_id;

  try {
    if (!isPermanentTenant) {
      console.log(`Dismissing temp notification for user: ${userId}`);
      await pool.query(
        "UPDATE temp_tenant_users SET rejection_message = NULL WHERE id = $1",
        [userId],
      );

      return res.json({
        success: true,
        message: "Temporary notification dismissed",
      });
    } else {
      console.log(
        `Delete notification requested for Permanent Tenant: ${userId}`,
      );
      return res.json({
        success: true,
        message: "Notification deletion logged (Full implementation pending)",
      });
    }
  } catch (err) {
    console.error("Dismiss Notification Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Mark Notification as Read --------------------
router.put("/notification/read", async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const userId = req.user.id;
  // Permanent tenants have an estate_id assigned to their profile
  const isPermanentTenant = !!req.user.estate_id;

  try {
    if (!isPermanentTenant) {
      // 1. Logic for Temp Tenant: Set is_read to TRUE
      console.log(`Marking temp notification as read for user: ${userId}`);
      await pool.query(
        "UPDATE temp_tenant_users SET is_read = TRUE WHERE id = $1",
        [userId],
      );

      return res.json({
        success: true,
        message: "Temp notification marked as read",
      });
    } else {
      // 2. Placeholder for Permanent Tenant logic
      console.log(
        `Mark as read requested for Permanent Tenant: ${userId} in Estate: ${req.user.estate_id}`,
      );
      // Future: await pool.query("UPDATE notifications SET is_read = TRUE WHERE user_id = $1", [userId]);

      return res.json({
        success: true,
        message: "Permanent tenant read status logged (Implementation pending)",
      });
    }
  } catch (err) {
    console.error("Read Notification Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/estates", async (req, res) => {
  try {
    const query = `
      SELECT 
        id, 
        name, 
        estate_code, 
        created_at,
        address,
        lga AS city,
        town,
        kyc_selection
      FROM estates 
      ORDER BY name ASC
    `;

    const result = await pool.query(query);

    res.json({
      success: true,
      estates: result.rows,
    });
  } catch (err) {
    console.error("Fetch Estates Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Update Push Token (Secure) --------------------
router.post("/update-push-token", async (req, res) => {
  const userId = req.body.userId || req.user?.id;
  const { pushToken } = req.body;
  console.log("Push Token:", pushToken);

  if (!userId) {
    return res
      .status(401)
      .json({ error: "Unauthorized: User session not found." });
  }

  if (!pushToken) {
    return res.status(400).json({ error: "pushToken is required" });
  }

  try {
    const result = await pool.query(
      `UPDATE tenant_users SET push_token = $1 WHERE id = $2 RETURNING id, name`,
      [pushToken, userId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Tenant record not found" });
    }

    res.json({
      success: true,
      message: "Push token linked to your account",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("Update Push Token Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

export const ensureTempTenant = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  console.log("Unauthorized access attempt to temp tenant route");
  res.status(401).json({ error: "Unauthorized" });
};

// -------------------- Fetch All Tenants --------------------
router.get(
  "/tenants/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("view_residents", "residents_management"),
  async (req, res) => {
    try {
      const estateId = req.params.estate_id;
      const currentUserId = req.user?.id;

      if (!estateId) {
        return res
          .status(401)
          .json({ error: "Unauthorized: No estate assigned." });
      }

      const query = `
      SELECT id, name, email, phone, locations, avatar, 
      id_type, id_front_url, id_back_url, utility_bill_url, 
      estate_ids, push_token, parent_account_id, sub_users, contract_urls, created_at
      FROM tenant_users 
        WHERE $1 = ANY(estate_ids)
        ORDER BY name ASC
    `;

      const params = [estateId];

      const result = await pool.query(query, params);

      res.json({
        success: true,
        tenants: result.rows,
      });
    } catch (err) {
      console.error("Fetch tenants error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

router.post(
  "/tenant/tenants",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    try {
      const estateId = req.body.estate_id;
      console.log("Fetch tenants for estate:", estateId);
      const currentUserId = req.user?.id;
      const is_tenant = req.user.role === "TENANT";

      if (!estateId) {
        return res
          .status(401)
          .json({ error: "Unauthorized: No estate assigned." });
      }

      const query = `
        SELECT id, name, email, locations, avatar, estate_ids, push_token
        FROM tenant_users 
        WHERE $1 = ANY(estate_ids) AND id != $2
        ORDER BY name ASC`;

      const params = [estateId, currentUserId];

      const result = await pool.query(query, params);

      res.json({
        success: true,
        tenants: result.rows,
      });
    } catch (err) {
      console.error("Fetch tenants error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Delete Tenant --------------------
router.delete(
  "/tenant/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("delete_resident_account", "residents_management"),
  async (req, res) => {
    const { id } = req.params;
    const admin_estate_id = req.query.estate_id;

    try {
      await pool.query("BEGIN");

      // 1. Fetch current status of the tenant to check existing estate associations
      const tenantRes = await pool.query(
        "SELECT * FROM tenant_users WHERE id = $1",
        [id],
      );

      if (tenantRes.rows.length === 0) {
        await pool.query("ROLLBACK");
        return res.status(404).json({ error: "Tenant not found" });
      }

      const tenant = tenantRes.rows[0];

      const existingEstates = tenant.estate_ids || [];

      if (!existingEstates.includes(admin_estate_id)) {
        await pool.query("ROLLBACK");
        return res.status(403).json({
          error:
            "This tenant is not registered under your estate management scope.",
        });
      }

      await pool.query(
        "DELETE FROM invitations WHERE estate_id = $1 AND resident_id = $2",
        [admin_estate_id, id],
      );
      await pool.query(
        "DELETE FROM location_bookings WHERE estate_id = $1 AND resident_id = $2",
        [admin_estate_id, id],
      );
      await pool.query(
        "DELETE FROM estate_reports WHERE estate_id = $1 AND reporter_id = $2",
        [admin_estate_id, id],
      );
      await pool.query(
        "DELETE FROM service_requests WHERE estate_id = $1 AND resident_id = $2",
        [admin_estate_id, id],
      );
      await pool.query(
        "DELETE FROM posts WHERE estate_id = $1 AND author_id = $2",
        [admin_estate_id, id],
      );
      await pool.query(
        "DELETE FROM payment_logs WHERE estate_id = $1 AND resident_id = $2",
        [admin_estate_id, id],
      );

      // 2. Fetch the current estate name to populate the feedback object
      const estateRes = await pool.query(
        "SELECT name FROM estates WHERE id = $1",
        [admin_estate_id],
      );
      const estate_name = estateRes.rows[0]?.name || "Managed Estate";

      const feedbackObj = JSON.stringify({
        type: "decline",
        estate: estate_name,
        message:
          "Your resident access rights have been revoked for this estate.",
      });

      // Determine remaining elements after removal
      const remainingEstates = existingEstates.filter(
        (eId) => eId !== admin_estate_id,
      );

      // Filter sensitive credentials out of the baseline state mirror
      const { password: _p, ...safeTenantStateBefore } = tenant;
      let auditActionType = "TENANT_ACCESS_REVOKED";
      let auditDescription = `Admin revoked resident "${tenant.name}" access from estate "${estate_name}". Profile retained for alternative estates.`;
      let finalStateAfter = null;

      if (remainingEstates.length === 0) {
        auditActionType = "TENANT_ACCESS_REVOKED";
        auditDescription = `Admin completely purged resident "${tenant.name}" from the active database. Profile moved to temporary holdings.`;

        await pool.query(
          `INSERT INTO temp_tenant_users 
         (name, email, password, phone, role, rejection_message, is_read)
         VALUES ($1, $2, $3, $4, $5, $6, FALSE)
         RETURNING id, name, email, phone, role, rejection_message`,
          [
            tenant.name,
            tenant.email,
            tenant.password,
            tenant.phone,
            tenant.role || "TENANT",
            feedbackObj,
          ],
        );

        await pool.query("DELETE FROM tenant_users WHERE id = $1", [id]);

        await pool.query("COMMIT");

        // Log asynchronously after commit completes
        await createAppAuditLog(req, {
          estate_id: admin_estate_id,
          action_type: auditActionType,
          target_resource: "tenant_users",
          target_id: id,
          description: auditDescription,
          state_before: safeTenantStateBefore,
          state_after: {
            status: "moved_to_temp_holdings",
            payload_snapshot: safeTenantStateBefore,
          },
          urgency: "HIGH",
        });

        return res.json({
          success: true,
          action: "DELETED",
          message: `${tenant.name} removed from platform completely and moved to temporary holdings (No remaining estates).`,
        });
      } else {
        const updateRes = await pool.query(
          `UPDATE tenant_users 
         SET 
           estate_ids = array_remove(estate_ids, $1::uuid),
           locations = locations - $2::text
         WHERE id = $3
         RETURNING id, name, email, phone, estate_ids, locations`,
          [admin_estate_id, admin_estate_id, id],
        );

        finalStateAfter = updateRes.rows[0];

        const pushToken = tenant.push_token;
        if (pushToken) {
          const notificationTitle = "Access Revoked ⚠️";
          const notificationBody = `Your access rights for ${estate_name} have been revoked.`;
          const data = {
            type: "notification",
            subtype: "revocation",
            estate_id: admin_estate_id,
          };

          sendPushNotification(
            pushToken,
            notificationTitle,
            notificationBody,
            data,
          ).catch((err) =>
            console.error("Revocation Notification Failed:", err),
          );
        }

        await pool.query("COMMIT");

        await createAppAuditLog(req, {
          estate_id: admin_estate_id,
          action_type: auditActionType,
          target_resource: "tenant_users",
          target_id: id,
          description: auditDescription,
          state_before: safeTenantStateBefore,
          state_after: finalStateAfter,
          urgency: "HIGH",
        });

        return res.json({
          success: true,
          action: "STRIPPED",
          message: `${tenant.name}'s access has been successfully revoked from ${estate_name}. Core profile retained for alternative estates.`,
        });
      }
    } catch (err) {
      await pool.query("ROLLBACK").catch(() => {});
      console.error("Tenant Access Revocation Exception:", err);
      res.status(500).json({
        error: "Internal server error during tenant clearance processing.",
      });
    }
  },
);
// -------------------- Create Join Request --------------------
router.post(
  "/join-request",
  upload.fields([
    { name: "selfie", maxCount: 1 },
    { name: "idFront", maxCount: 1 },
    { name: "idBack", maxCount: 1 },
    { name: "utilityBill", maxCount: 1 },
    { name: "rentContract", maxCount: 20 },
  ]),
  async (req, res) => {
    let { tempTenantId, estateId, idType, locations } = req.body;
    console.log("Received Join Request:", {
      tempTenantId,
      estateId,
      idType,
      locations,
    });

    if (!tempTenantId || !estateId) {
      return res
        .status(400)
        .json({ error: "Id and Estate fields are required" });
    }

    try {
      const parsedLocations =
        typeof locations === "string" ? JSON.parse(locations) : locations || [];

      const estateCheck = await pool.query(
        `SELECT kyc_selection FROM estates WHERE id = $1`,
        [estateId],
      );
      if (estateCheck.rows.length === 0) {
        return res.status(404).json({ error: "Estate registry not found" });
      }

      const config = estateCheck.rows[0].kyc_selection || {
        selfie: true,
        rent_contract: true,
      };

      // Base Validations
      if (config.selfie && (!req.files || !req.files["selfie"]))
        return res.status(400).json({ error: "Selfie is required." });
      if (config.ids && (!req.files || !req.files["idFront"]))
        return res.status(400).json({ error: "ID card frame is required." });
      if (config.utility_bill && (!req.files || !req.files["utilityBill"]))
        return res.status(400).json({ error: "Utility bill is required." });

      const totalUnitsCount = parsedLocations.reduce(
        (sum, b) => sum + b.units.length,
        0,
      );

      if (config.rent_contract) {
        if (
          !req.files ||
          !req.files["rentContract"] ||
          req.files["rentContract"].length !== totalUnitsCount
        ) {
          return res.status(400).json({
            error: `Validation error: You must upload exactly ${totalUnitsCount} rent contract file(s)—one regarding each unit entered.`,
          });
        }
      }

      const existingReq = await pool.query(
        `SELECT id FROM join_requests WHERE temp_tenant_id = $1`,
        [tempTenantId],
      );
      if (existingReq.rows.length > 0)
        return res
          .status(409)
          .json({ error: "Only one pending application is allowed." });

      const fields = ["selfie", "idFront", "idBack", "utilityBill"];
      const singleUploadPromises = fields.map(async (field) => {
        const file = req.files?.[field]?.[0];
        if (!file) return { field, url: null };

        const url = await uploadToS3Direct(
          file.buffer,
          file.mimetype,
          "gateman_tenant_kyc",
          file.originalname,
        );
        return { field, url };
      });

      // 2. Process Multi-File Rent Contracts Concurrently
      let rentContractPromises = [];
      if (config.rent_contract && req.files?.["rentContract"]) {
        rentContractPromises = req.files["rentContract"].map((file) =>
          uploadToS3Direct(
            file.buffer,
            file.mimetype,
            "gateman_tenant_contracts",
            file.originalname,
          ),
        );
      }

      // Execute all single-field and multi-contract uploads simultaneously
      const [singleResults, rentContractUrls] = await Promise.all([
        Promise.all(singleUploadPromises),
        Promise.all(rentContractPromises),
      ]);

      // Map single results to key-value lookup
      const singleUploadTasks = singleResults.reduce((acc, { field, url }) => {
        acc[field] = url;
        return acc;
      }, {});

      let contractUrlIndex = 0;
      const structuredLocations = parsedLocations.map((blockObj) => ({
        block: blockObj.block.trim(),
        units: blockObj.units.map((unitName) => {
          const unitObj = { unit: unitName.trim(), contract_url: null };
          if (config.rent_contract) {
            unitObj.contract_url = rentContractUrls[contractUrlIndex] || null;
            contractUrlIndex++;
          }
          return unitObj;
        }),
      }));

      const result = await pool.query(
        `INSERT INTO join_requests 
         (temp_tenant_id, estate_id, id_type, selfie_url, id_front_url, id_back_url, utility_bill_url, locations)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)
         RETURNING *`,
        [
          tempTenantId,
          estateId,
          idType || null,
          singleUploadTasks["selfie"] || null,
          singleUploadTasks["idFront"] || null,
          singleUploadTasks["idBack"] || null,
          singleUploadTasks["utilityBill"] || null,
          JSON.stringify(structuredLocations),
        ],
      );

      res.status(201).json({ success: true, joinRequest: result.rows[0] });
    } catch (err) {
      console.error("KYC JSONB Processing Crash:", err);
      res
        .status(500)
        .json({ error: "Internal server error sorting request structures." });
    }
  },
);

// -------------------- Fetch All Join Requests --------------------
router.get(
  "/join-requests/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("view_residents", "residents_management"),
  async (req, res) => {
    const estateId = req.params.estate_id;

    // Guard clause against missing query params
    if (!estateId) {
      return res
        .status(400)
        .json({ error: "Missing required estate_id parameter" });
    }

    try {
      const result = await pool.query(
        `SELECT 
           jr.*, 
           COALESCE(tt.name, pt.name) AS temp_tenant_name, 
           COALESCE(tt.email, pt.email) AS temp_tenant_email, 
           COALESCE(tt.phone, pt.phone) AS temp_tenant_phone,
           CASE WHEN pt.id IS NOT NULL THEN 'permanent' ELSE 'temporary' END AS tenant_type
         FROM join_requests jr
         LEFT JOIN temp_tenant_users tt ON jr.temp_tenant_id = tt.id
         LEFT JOIN tenant_users pt ON jr.temp_tenant_id = pt.id 
         WHERE jr.estate_id = $1
         ORDER BY jr.requested_at DESC`,
        [estateId],
      );

      res.json({
        success: true,
        joinRequests: result.rows,
      });
    } catch (err) {
      console.error("Fetch Join Requests Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Approve Tenant --------------------
router.post(
  "/approve-tenant/:joinRequestId",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("manage_join_requests", "residents_management"),
  async (req, res) => {
    const { joinRequestId } = req.params;
    const admin = req.user;
    const estateId = req.query.estate_id;
    let estateRawlocations = {};

    try {
      const jrCheck = await pool.query(
        `SELECT * FROM join_requests WHERE id = $1`,
        [joinRequestId],
      );

      if (jrCheck.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Join request not found or already processed." });
      }
      const joinRequest = jrCheck.rows[0];

      const estateCheck = await pool.query(
        `SELECT name FROM estates WHERE id = $1`,
        [estateId],
      );

      const estateName =
        estateCheck.rows.length > 0 ? estateCheck.rows[0].name : "your estate";

      await pool.query("BEGIN");

      const rawLocations =
        typeof joinRequest.locations === "string"
          ? JSON.parse(joinRequest.locations)
          : joinRequest.locations;

      estateRawlocations[estateId] = rawLocations;

      const incomingLocationsArray = Array.isArray(rawLocations)
        ? rawLocations.map((loc) => ({
            block: loc.block ? String(loc.block).trim() : "",
            unit: Array.isArray(loc.units)
              ? loc.units.map((u) =>
                  typeof u === "object"
                    ? String(u.unit).trim()
                    : String(u).trim(),
                )
              : [],
          }))
        : [];

      let processedTenant;
      let isTransitionFromTemp = true;

      const permanentCheck = await pool.query(
        `SELECT * FROM tenant_users WHERE id = $1`,
        [joinRequest.temp_tenant_id],
      );

      if (permanentCheck.rows.length > 0) {
        isTransitionFromTemp = false;
        const existingTenant = permanentCheck.rows[0];

        const currentEstateIds = existingTenant.estate_ids || [];
        const updatedEstateIds = currentEstateIds.includes(estateId)
          ? currentEstateIds
          : [...currentEstateIds, estateId];

        const currentLocationsMap =
          typeof existingTenant.locations === "string"
            ? JSON.parse(existingTenant.locations)
            : existingTenant.locations || {};

        currentLocationsMap[estateId] = incomingLocationsArray;

        const currentContractUrlsMap =
          typeof existingTenant.contract_urls === "string"
            ? JSON.parse(existingTenant.contract_urls)
            : existingTenant.contract_urls || {};

        currentContractUrlsMap[estateId] = rawLocations;

        const currentAvatarsMap =
          typeof existingTenant.avatar === "string"
            ? JSON.parse(existingTenant.avatar)
            : existingTenant.avatar || {};

        currentAvatarsMap[estateId] = joinRequest.selfie_url || "";

        const updateRes = await pool.query(
          `UPDATE tenant_users 
           SET estate_ids = $1, locations = $2, contract_urls = $3, avatar = $4
           WHERE id = $5 
           RETURNING *`,
          [
            updatedEstateIds,
            JSON.stringify(currentLocationsMap),
            JSON.stringify(currentContractUrlsMap),
            JSON.stringify(currentAvatarsMap),
            existingTenant.id,
          ],
        );

        processedTenant = updateRes.rows[0];

        // --- INSERT DATABASE NOTIFICATION ---
        const notificationTitle = "Residency Approved! 🎉";
        const notificationMessage = `Your residency at ${estateName} has been approved.`;

        const notificationRes = await pool.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'tenant', $3, $4, 'announcement') RETURNING *`,
          [
            estateId,
            processedTenant.id,
            notificationTitle,
            notificationMessage,
          ],
        );

        const pushToken = processedTenant.push_token;
        if (pushToken) {
          const data = {
            type: "notification",
            subtype: "approval",
            estate_id: estateId,
          };

          sendPushNotification(
            pushToken,
            notificationTitle,
            notificationMessage,
            data,
          ).catch((err) => console.error("Approval Notification Failed:", err));
        }

        io.to(`user_${processedTenant.id}`).emit(
          "status_update",
          notificationRes.rows[0],
        );
      } else {
        const tempRes = await pool.query(
          `SELECT * FROM temp_tenant_users WHERE id = $1`,
          [joinRequest.temp_tenant_id],
        );

        if (tempRes.rows.length === 0) {
          await pool.query("ROLLBACK");
          return res.status(404).json({
            error:
              "Applicant reference profile context not found in any registration table.",
          });
        }
        const temp = tempRes.rows[0];

        const estateIdsArray = [estateId];
        const formattedLocationsMap = { [estateId]: incomingLocationsArray };
        const initialContractUrlsMap = { [estateId]: rawLocations };
        const initialAvatarsMap = { [estateId]: joinRequest.selfie_url || "" };

        const insertRes = await pool.query(
          `INSERT INTO tenant_users (
            name, email, password, phone, role,
            estate_ids, locations, avatar, 
            id_type, id_front_url, id_back_url, utility_bill_url,
            first_login, contract_urls
          ) VALUES ($1, $2, $3, $4, 'TENANT', $5, $6, $7, $8, $9, $10, $11, true, $12)
           RETURNING *`,
          [
            temp.name,
            temp.email,
            temp.password,
            temp.phone,
            estateIdsArray,
            JSON.stringify(formattedLocationsMap),
            JSON.stringify(initialAvatarsMap),
            joinRequest.id_type,
            joinRequest.id_front_url,
            joinRequest.id_back_url,
            joinRequest.utility_bill_url,
            JSON.stringify(initialContractUrlsMap),
          ],
        );

        processedTenant = insertRes.rows[0];

        const feedbackObj = JSON.stringify({
          type: "approve",
          estate: estateName,
          message:
            "Your residency has been approved! Please log out and log back in to access your new tenant dashboard.",
        });

        await pool.query(
          "UPDATE temp_tenant_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
          [feedbackObj, temp.id],
        );

        const notification = {
          from: estateName,
          type: "announcement",
          message:
            "Your residency has been approved! Please log out and log back in to access your new tenant dashboard.",
          reason: "Estate residency join request approved.",
        };

        io.to(`user_${temp.id}`).emit("status_update", notification);

      }

      await pool.query("DELETE FROM join_requests WHERE id = $1", [
        joinRequestId,
      ]);
      await pool.query("COMMIT");

      if (processedTenant.email) {
        sendTenantApprovalEmail(
          processedTenant.email,
          processedTenant.name,
          estateName,
        ).catch((err) => console.error("Approval Email Failed:", err));
      }

      res.json({
        success: true,
        message: `${processedTenant.name} has been successfully processed and verified for this estate scope.`,
        tenant: processedTenant,
      });

      const { password: _p, ...safeTenantState } = processedTenant;

      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: isTransitionFromTemp
          ? "TENANT_ONBOARDING_APPROVED"
          : "TENANT_NEW_ESTATE_ADDED",
        target_resource: "tenant_users",
        target_id: processedTenant.id,
        description: `Admin approved residency request for "${processedTenant.name}". ${
          isTransitionFromTemp
            ? "Created new permanent profile row."
            : "Appended new estate to profile map."
        }`,
        state_before: isTransitionFromTemp
          ? joinRequest
          : permanentCheck.rows[0],
        state_after: safeTenantState,
        urgency: "HIGH",
      });
    } catch (err) {
      await pool.query("ROLLBACK").catch(() => {});
      console.error("Multi-Tier Approval Error:", err);
      res.status(500).json({
        error: "Internal server error execution block runtime crash.",
      });
    }
  },
);

// -------------------- Manual Resident Onboarding --------------------
router.post(
  "/residents/manual-add",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("add_resident", "residents_management"),
  async (req, res) => {
    const {
      name,
      email,
      phone,
      locations: rawLocationsJson,
      selfie,
      rentContract: rawRentContractJson,
      estate_id: adminEstateId,
    } = req.body;

    const client = await pool.connect();

    try {
      const parsedLocations =
        typeof rawLocationsJson === "string"
          ? JSON.parse(rawLocationsJson)
          : rawLocationsJson || [];

      const parsedContracts =
        typeof rawRentContractJson === "string"
          ? JSON.parse(rawRentContractJson)
          : rawRentContractJson || [];

      const targetLocationsArray = Array.isArray(parsedLocations)
        ? parsedLocations.map((loc) => ({
            block: loc.block ? String(loc.block).trim() : "",
            unit: Array.isArray(loc.units)
              ? loc.units.map((u) =>
                  typeof u === "object" && u !== null
                    ? String(u.unit).trim()
                    : String(u).trim(),
                )
              : [],
          }))
        : [];

      let contractUrlsCounter = 0;

      const newContractUrls = Array.isArray(parsedLocations)
        ? parsedLocations.map((loc) => ({
            block: loc.block ? String(loc.block).trim() : "",
            units: Array.isArray(loc.units)
              ? loc.units.map((u) => {
                  const unitName =
                    typeof u === "object" && u !== null
                      ? String(u.unit).trim()
                      : String(u).trim();

                  const associatedContract =
                    Array.isArray(parsedContracts) &&
                    parsedContracts[contractUrlsCounter]
                      ? parsedContracts[contractUrlsCounter].uri ||
                        parsedContracts[contractUrlsCounter]
                      : "";

                  contractUrlsCounter++;

                  return {
                    unit: unitName,
                    contract_url: associatedContract,
                  };
                })
              : [],
          }))
        : [];

      const existingUserCheck = await client.query(
        "SELECT * FROM tenant_users WHERE email = $1 OR phone = $2",
        [email, phone],
      );

      let finalProcessedTenant;
      let isNewUser = true;
      let generatedPassword = null;
      let fullCombinedPassword = null; // Scoped outside so email dispatch can read it

      await client.query("BEGIN");

      // Fetch estate name inside transaction for notification payload
      const estateCheck = await client.query(
        "SELECT name FROM estates WHERE id = $1",
        [adminEstateId],
      );
      const estateName =
        estateCheck.rows.length > 0 ? estateCheck.rows[0].name : "your estate";

      if (existingUserCheck.rows.length > 0) {
        isNewUser = false;
        const existingTenant = existingUserCheck.rows[0];

        const estateIdsArray = existingTenant.estate_ids || [];
        const updatedEstateIds = estateIdsArray.includes(adminEstateId)
          ? estateIdsArray
          : [...estateIdsArray, adminEstateId];

        const currentLocationsMap =
          typeof existingTenant.locations === "string"
            ? JSON.parse(existingTenant.locations)
            : existingTenant.locations || {};
        currentLocationsMap[adminEstateId] = targetLocationsArray;

        const currentContractUrlsMap =
          typeof existingTenant.contract_urls === "string"
            ? JSON.parse(existingTenant.contract_urls)
            : existingTenant.contract_urls || {};
        currentContractUrlsMap[adminEstateId] = newContractUrls;

        const currentAvatarsMap =
          typeof existingTenant.avatar === "string"
            ? JSON.parse(existingTenant.avatar)
            : existingTenant.avatar || {};
        currentAvatarsMap[adminEstateId] = selfie || "";

        const updateRes = await client.query(
          `UPDATE tenant_users 
           SET estate_ids = $1, locations = $2, contract_urls = $3, avatar = $4
           WHERE id = $5 
           RETURNING *`,
          [
            updatedEstateIds,
            JSON.stringify(currentLocationsMap),
            JSON.stringify(currentContractUrlsMap),
            JSON.stringify(currentAvatarsMap),
            existingTenant.id,
          ],
        );
        finalProcessedTenant = updateRes.rows[0];
      } else {
        const emailPasswordPart = crypto.randomBytes(3).toString("hex");
        const smsPasswordPart = "gate";
        fullCombinedPassword = emailPasswordPart + smsPasswordPart;

        const saltRounds = 10;
        const secureHashedPassword = await bcrypt.hash(
          fullCombinedPassword,
          saltRounds,
        );

        const estateIdsArray = [adminEstateId];
        const initialLocationsMap = { [adminEstateId]: targetLocationsArray };
        const initialContractUrlsMap = { [adminEstateId]: newContractUrls };
        const initialAvatarsMap = { [adminEstateId]: selfie || "" };

        const insertRes = await client.query(
          `INSERT INTO tenant_users (
             name, email, password, phone, role,
             estate_ids, locations, avatar, 
             first_login, contract_urls, created_at
           ) VALUES ($1, $2, $3, $4, 'TENANT', $5, $6, $7, true, $8, NOW())
           RETURNING *`,
          [
            name,
            email,
            secureHashedPassword,
            phone,
            estateIdsArray,
            JSON.stringify(initialLocationsMap),
            JSON.stringify(initialAvatarsMap),
            JSON.stringify(initialContractUrlsMap),
          ],
        );
        finalProcessedTenant = insertRes.rows[0];

        generatedPassword = {
          emailPart: emailPasswordPart,
          smsPart: smsPasswordPart,
        };
      }

      // --- INSERT DATABASE NOTIFICATION ---
      const notificationTitle = "Welcome to the Estate! 🎉";
      const notificationMessage = `You have been added to ${estateName}. Welcome aboard!`;

      await client.query(
        `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
         VALUES ($1, $2, 'tenant', $3, $4, 'announcement')`,
        [
          adminEstateId,
          finalProcessedTenant.id,
          notificationTitle,
          notificationMessage,
        ],
      );

      await client.query("COMMIT");
      client.release();

      const { password: _p, ...safeTenantState } = finalProcessedTenant;

      // Dispatches welcome notifications for new users safely
      if (isNewUser && generatedPassword) {
        if (phone) {
          try {
            await sendTenantWelcomeEmail(
              email,
              name,
              generatedPassword.emailPart,
            );
            console.log(`Onboarding email split token dispatched to ${email}`);
          } catch (emailErr) {
            console.error("Non-fatal email dispatch error:", emailErr);
          }

          console.log(
            `[TEST MODE SMS TOKEN SIMULATION] Phone: ${phone} | Token: ${generatedPassword.smsPart}`,
          );
        } else {
          try {
            await sendTenantWelcomeEmail(email, name, fullCombinedPassword);
            console.log(
              `Onboarding full password email dispatched to ${email}`,
            );
          } catch (emailErr) {
            console.error("Non-fatal email dispatch error:", emailErr);
          }
        }
      }

      // Audit log execution without blocking request return
      if (typeof createAppAuditLog !== "undefined") {
        createAppAuditLog(req, {
          estate_id: adminEstateId,
          action_type: isNewUser
            ? "MANUAL_TENANT_CREATED"
            : "MANUAL_TENANT_ESTATE_APPENDED",
          target_resource: "tenant_users",
          target_id: finalProcessedTenant.id,
          description: `Admin manually provisioned tenant entry configuration for "${name}".`,
          state_before: isNewUser ? null : existingUserCheck.rows[0],
          state_after: safeTenantState,
          urgency: "HIGH",
        }).catch((logErr) => console.error("Audit logger error:", logErr));
      }

      return res.json({
        success: true,
        message:
          "Resident successfully introduced into system directory manually.",
        tenant: safeTenantState,
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      client.release();

      console.error("Manual Onboarding API Execution Fail:", err);
      return res.status(500).json({
        error: "Internal server error processing manual resident setup.",
      });
    }
  },
);

// -------------------- Decline Join Request --------------------
router.delete(
  "/join-request/delete",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("manage_join_requests", "residents_management"), // Matches permission name in DB
  async (req, res) => {
    const { id, message, estate_id: estateId } = req.body;

    // Dedicated pool connection for isolated transaction
    const client = await pool.connect();

    try {
      // 🧠 Fetch target snapshot prior to removal
      const infoRes = await client.query(
        `SELECT jr.*, e.name as estate_name 
         FROM join_requests jr 
         JOIN estates e ON jr.estate_id = e.id 
         WHERE jr.id = $1`,
        [id],
      );

      if (infoRes.rows.length === 0) {
        client.release();
        return res.status(404).json({ error: "Request not found" });
      }

      const joinRequestData = infoRes.rows[0];
      const { temp_tenant_id, estate_name } = joinRequestData;

      const feedbackObj = JSON.stringify({
        type: "decline",
        estate: estate_name,
        message: message || "",
      });

      await client.query("BEGIN");
      await client.query(
        "UPDATE temp_tenant_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
        [feedbackObj, temp_tenant_id],
      );
      await client.query("DELETE FROM join_requests WHERE id = $1", [id]);
      await client.query("COMMIT");

      // Release connection back to pool
      client.release();

      // 1. Respond to admin client instantly
      res.json({
        success: true,
        message: "Request declined and user notified.",
      });

      // 2. Trace rejection audit row asynchronously
      createAppAuditLog(req, {
        estate_id: estateId || joinRequestData.estate_id,
        action_type: "TENANT_ONBOARDING_DECLINED",
        target_resource: "join_requests",
        target_id: id,
        description: `Admin declined onboarding application request for applicant reference token: ${temp_tenant_id}. Reason provided: "${message || "None Specified"}".`,
        state_before: joinRequestData,
        state_after: { response_delivery: JSON.parse(feedbackObj) },
        urgency: "HIGH",
      }).catch((auditErr) =>
        console.error("Audit log creation error:", auditErr),
      );
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      client.release();

      console.error("Delete Join Request Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);
// -------------------- Block Tenant via Admin Table --------------------
router.put(
  "/join-request/block",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("manage_join_requests", "residents_management"), // Added: checks permission
  async (req, res) => {
    const { id, message, estate_id: estateId } = req.body;

    // 1. Acquire dedicated client for isolated transaction safety
    const client = await pool.connect();

    try {
      // 🧠 Fetch targeted data structure details before destroying the relation
      const infoRes = await client.query(
        `SELECT jr.*, e.name as estate_name 
         FROM join_requests jr 
         JOIN estates e ON jr.estate_id = e.id 
         WHERE jr.id = $1`,
        [id],
      );

      if (infoRes.rows.length === 0) {
        client.release();
        return res.status(404).json({ error: "Request not found" });
      }

      const joinRequestData = infoRes.rows[0];
      const { temp_tenant_id, estate_name } = joinRequestData;

      const feedbackObj = JSON.stringify({
        type: "block",
        estate: estate_name,
        message: message || "You have been restricted from this estate.",
      });

      // 2. Open transaction on dedicated client
      await client.query("BEGIN");

      // Add to Admin's Block List
      await client.query(
        `UPDATE estates 
         SET blocked_tenant_ids = array_append(blocked_tenant_ids, $1) 
         WHERE id = $2 AND NOT ($1 = ANY(blocked_tenant_ids))`,
        [temp_tenant_id, estateId || joinRequestData.estate_id],
      );

      const tempTenantRes = await client.query(
        `UPDATE temp_tenant_users 
         SET rejection_message = $1, is_read = FALSE 
         WHERE id = $2 
         RETURNING name`,
        [feedbackObj, temp_tenant_id],
      );

      const tenantName = tempTenantRes.rows[0]?.name || "Unknown Applicant";

      await client.query("DELETE FROM join_requests WHERE id = $1", [id]);
      await client.query("COMMIT");

      // 3. Always release client back to the pool
      client.release();

      // 4. Respond to admin client instantly
      res.json({ success: true, message: "User blocked and request removed." });

      // 5. Trace blacklisting row footprint asynchronously
      createAppAuditLog(req, {
        estate_id: estateId || joinRequestData.estate_id,
        action_type: "TENANT_BLACKLISTED",
        target_resource: "join_requests",
        target_id: id,
        description: `Admin blacklisted candidate ${tenantName} from ever requesting to join the estate context map again.`,
        state_before: joinRequestData,
        state_after: {
          execution_enforcement: "HARD_BLOCK_ENFORCED",
          block_payload: JSON.parse(feedbackObj),
        },
        urgency: "HIGH",
      }).catch((auditErr) => console.error("Audit log error:", auditErr));
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      client.release();

      console.error("Block Join Request Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Fetch Blocked Users (Optimized) --------------------
router.get(
  "/blocked-users/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("view_residents", "residents_management"),
  async (req, res) => {
    const estateId = req.params.estate_id;

    // Guard clause against missing query params
    if (!estateId) {
      return res
        .status(400)
        .json({ error: "Missing required estate_id parameter" });
    }

    try {
      const result = await pool.query(
        `SELECT id, name, email 
       FROM temp_tenant_users 
       WHERE id = ANY(
         SELECT unnest(blocked_tenant_ids) 
         FROM estates 
         WHERE id = $1
       )`,
        [estateId],
      );

      res.json({
        success: true,
        blockedUsers: result.rows,
      });
    } catch (err) {
      console.error("Fetch Blocked Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

router.put(
  "/join-request/unblock",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("manage_join_requests", "residents_management"),
  async (req, res) => {
    const { tempTenantId, estate_id: estateId } = req.body;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Remove the specific ID from the estate's blocked_tenant_ids array
      const estateRes = await client.query(
        `UPDATE estates 
         SET blocked_tenant_ids = array_remove(blocked_tenant_ids, $1) 
         WHERE id = $2
         RETURNING id`,
        [tempTenantId, estateId], // Fixed: passed estateId instead of adminId
      );

      if (estateRes.rows.length === 0) {
        await client.query("ROLLBACK");
        client.release();
        return res.status(404).json({ error: "Estate record not found." });
      }

      // 2. Clear the rejection/block message
      const tempTenantRes = await client.query(
        `UPDATE temp_tenant_users 
         SET rejection_message = NULL 
         WHERE id = $1 
         RETURNING name`,
        [tempTenantId],
      );

      if (tempTenantRes.rows.length === 0) {
        await client.query("ROLLBACK");
        client.release();
        return res
          .status(404)
          .json({ error: "Temporary tenant profile reference missing." });
      }

      const tenantName = tempTenantRes.rows[0].name;

      await client.query("COMMIT");
      client.release();

      // 3. Respond to admin client instantly
      res.json({ success: true, message: "User has been unblocked." });

      // 4. Trace whitelist status reversal asynchronously
      createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "TENANT_UNBLOCKED",
        target_resource: "temp_tenant_users",
        target_id: tempTenantId,
        description: `Admin unblocked candidate "${tenantName}" (ID: ${tempTenantId}), restoring their right to submit estate entry registration join requests.`,
        state_before: { status: "BLOCKED", temp_tenant_id: tempTenantId },
        state_after: {
          status: "RESTORED_PENDING_SUBMISSION",
          rejection_message: null,
        },
        urgency: "HIGH",
      }).catch((auditErr) => console.error("Audit log error:", auditErr));
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      client.release();

      console.error("Unblock Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Group Push Notification Dispatcher --------------------
router.post("/send-group-notification", async (req, res) => {
  const { memberIds, text, roomId, senderName, groupName } = req.body;
  const currentUserId = req.user?.id; // Authenticated sender

  if (!memberIds || !Array.isArray(memberIds)) {
    return res.status(400).json({ error: "memberIds array is required" });
  }

  const uuidIds = memberIds.filter(
    (id) => typeof id === "string" && id.length > 0,
  );

  try {
    const result = await pool.query(
      `SELECT push_token FROM tenant_users 
       WHERE id = ANY($1::uuid[]) AND id != $2::uuid AND push_token IS NOT NULL`,
      [uuidIds, currentUserId],
    );

    const targetTokens = result.rows.map((r) => r.push_token);

    if (targetTokens.length === 0) {
      return res.json({
        success: true,
        message: "No recipients with push tokens found.",
      });
    }

    // 2. Prepare the Expo notification batch
    const notifications = targetTokens.map((token) => ({
      to: token,
      sound: "default",
      title: groupName || "Estate Group",
      body: `${senderName}: ${text || "Sent an attachment"}`,
      data: {
        type: "chat",
        roomId: roomId,
        isGroup: true,
        senderName: senderName,
      },
      channelId: "default",
    }));

    // 3. Fire to Expo (Backend to Backend)
    await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(notifications),
    });

    res.json({ success: true, count: targetTokens.length });
  } catch (err) {
    console.error("Group Push Error:", err);
    res
      .status(500)
      .json({ error: "Internal server error dispatching group push" });
  }
});

// POST /api/auth/send-otp
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
    `SELECT id FROM estate_admin_users 
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

router.post("/tenant/send-otp", async (req, res) => {
  console.log("profile otp api hit");
  const { target, type } = req.body;
  const tenantId = req.user.id;
  let normalizedTarget;
  if (type === "email") {
    normalizedTarget = target.trim().toLowerCase();
  } else {
    normalizedTarget = target.trim();
  }
  console.log("Generated Normalized Target:", normalizedTarget);

  const checkUser = await pool.query(
    `SELECT id FROM tenant_users 
       WHERE (LOWER(email) = $1 OR phone = $1) 
       AND id != $2`,
    [normalizedTarget, tenantId],
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

router.post("/security/send-otp", async (req, res) => {
  console.log("security profile otp api hit");
  const { target, type } = req.body;
  const securityId = req.user.id;
  let normalizedTarget;
  if (type === "email") {
    normalizedTarget = target.trim().toLowerCase();
  } else {
    normalizedTarget = target.trim();
  }
  console.log("Generated Normalized Target:", normalizedTarget);

  const checkUser = await pool.query(
    `SELECT id FROM security_users 
       WHERE (LOWER(email) = $1 OR phone = $1) 
       AND id != $2`,
    [normalizedTarget, securityId],
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

router.post("/tenant/update-config", async (req, res) => {
  const email = req.body.email?.trim() || req.user.email;
  const phone = req.body.phone?.trim() || req.user.phone || null;
  const biometric_login =
    req.body.biometric_login ?? req.user.biometric_login ?? false;

  const userId = req.user.id;
  const isTemp = req.user.isTemp === true;
  const tableName = isTemp ? "temp_tenant_users" : "tenant_users";

  const client = await pool.connect();
  try {
    await client.query("BEGIN");
    let updateQuery;
    let values;

    if (isTemp) {
      updateQuery = `
        UPDATE ${tableName} 
        SET email = $1, phone = $2 
        WHERE id = $3 
        RETURNING *`;
      values = [email, phone, userId];
    } else {
      updateQuery = `
        UPDATE ${tableName} 
        SET email = $1, phone = $2, biometric_login = $3 
        WHERE id = $4 
        RETURNING *`;
      values = [email, phone, biometric_login, userId];
    }

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) throw new Error("User not found");

    await client.query("COMMIT");
    const updatedUser = result.rows[0];
    delete updatedUser.password;

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.code === "23505") {
      return res.status(400).json({
        success: false,
        message: "Email or Phone number is already in use.",
      });
    }
    res.status(500).json({ success: false, message: "Internal server error" });
  } finally {
    client.release();
  }
});

router.post("/security/update-config", async (req, res) => {
  const email = req.body.email?.trim() || req.user.email;
  const phone = req.body.phone?.trim() || req.user.phone || null;
  const biometric_login =
    req.body.biometric_login ?? req.user.biometric_login ?? false;

  const userId = req.user.id;
  const isTemp = req.user.isTemp === true;
  const tableName = isTemp ? "temp_security_users" : "security_users";

  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    let updateQuery;
    let values;

    if (isTemp) {
      updateQuery = `
        UPDATE ${tableName} 
        SET email = $1, phone = $2 
        WHERE id = $3 
        RETURNING *`;
      values = [email, phone, userId];
    } else {
      updateQuery = `
        UPDATE ${tableName} 
        SET email = $1, phone = $2, biometric_login = $3 
        WHERE id = $4 
        RETURNING *`;
      values = [email, phone, biometric_login, userId];
    }
    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) throw new Error("User not found");

    await client.query("COMMIT");
    const updatedUser = result.rows[0];
    delete updatedUser.password;

    res.json({
      success: true,
      message: "Profile updated successfully",
      user: updatedUser,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    if (err.code === "23505") {
      return res.status(400).json({
        success: false,
        message: "Email or Phone number is already in use.",
      });
    }
    res.status(500).json({ success: false, message: "Internal server error" });
  } finally {
    client.release();
  }
});

// -------------------- Update Estate Configuration --------------------
router.post(
  "/update-config",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    console.log("Update config api hit");
    const { config, estate_id: estateId } = req.body;
    const adminId = req.user.id;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Update Admin User
      const adminQuery = `
      UPDATE estate_admin_users 
      SET name = $1, 
          email = $2, 
          phone_number = $3, 
          mfa_enabled = $4,
          mfa_type = $5, 
          mfa_secret = $6,
          avatar = $7
      WHERE id = $8 
      RETURNING *`;

      const adminValues = [
        config.admin_name,
        config.email,
        config.phone_number,
        config.mfa_enabled,
        config.mfa_type,
        config.mfa_secret,
        config.avatar,
        adminId,
      ];
      const adminResult = await client.query(adminQuery, adminValues);

      // 2. Update Estate Configs
      const estateQuery = `
      UPDATE estates 
      SET 
        bank_name = $1, 
        bank_code = $2, 
        bank_account_number = $3, 
        bank_account_name = $4,
        payment_type = $5,
        external_api_url = $6,
        emergency_contacts = $7
      WHERE id = $8`;

      const estateValues = [
        config.bank_details.bank_name,
        config.bank_details.bank_code,
        config.bank_details.account_number,
        config.bank_details.account_name,
        config.payment_type,
        config.external_api_url,
        JSON.stringify(config.emergency_contacts),
        estateId,
      ];
      await client.query(estateQuery, estateValues);

      await client.query("COMMIT");

      const updatedUser = {
        ...adminResult.rows[0],
        bank_name: config.bank_details.bank_name,
        bank_code: config.bank_details.bank_code,
        bank_account_number: config.bank_details.account_number,
        bank_account_name: config.bank_details.account_name,
        payment_type: config.payment_type,
        external_api_url: config.external_api_url,
        emergency_contacts: config.emergency_contacts,
        estate_id: estateId,
      };

      res.json({
        success: true,
        message: "Configuration updated successfully",
        user: updatedUser,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Update Config Error:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal server error" });
    } finally {
      client.release();
    }
  },
);

router.post(
  "/payment-settings",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    try {
      const estateId = req.body.estate_id;

      if (!estateId) {
        return res
          .status(400)
          .json({ success: false, error: "Estate ID not found in session." });
      }

      const query = `
      SELECT 
        payment_type, 
        bank_name, 
        bank_account_number, 
        bank_account_name, 
        external_api_url 
      FROM estates 
      WHERE id = $1
    `;

      const result = await pool.query(query, [estateId]);

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({ success: false, error: "Estate settings not found." });
      }

      const estate = result.rows[0];
      const mode = estate.payment_type;

      // Constructing the response dynamically
      const responseData = {
        payment_type: mode,
        details:
          mode === "api"
            ? { external_api_url: estate.external_api_url }
            : {
                bank_name: estate.bank_name,
                bank_account_number: estate.bank_account_number,
                bank_account_name: estate.bank_account_name,
              },
      };

      res.status(200).json({
        success: true,
        data: responseData,
      });
    } catch (error) {
      console.error("Error fetching payment settings:", error);
      res.status(500).json({ success: false, error: "Internal server error" });
    }
  },
);

// GET /api/estates/emergency-contacts
router.get("/emergency-contacts", async (req, res) => {
  const { estate_id } = req.user;

  try {
    const query = `SELECT emergency_contacts FROM estates WHERE id = $1`;
    const result = await pool.query(query, [estate_id]);

    if (result.rows.length === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Estate not found" });
    }

    let rawData = result.rows[0].emergency_contacts;

    // Parse if it's a string, otherwise use as is
    const contacts =
      typeof rawData === "string" ? JSON.parse(rawData) : rawData;

    res.json({ success: true, contacts: contacts || [] });
  } catch (err) {
    console.error("Fetch Emergency Contacts Error:", err);
    res.status(500).json({ success: false, message: "Internal server error" });
  }
});

router.post(
  "/emergency-contacts",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    const { estate_id } = req.body;

    try {
      const query = `SELECT emergency_contacts FROM estates WHERE id = $1`;
      const result = await pool.query(query, [estate_id]);

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "Estate not found" });
      }

      let rawData = result.rows[0].emergency_contacts;

      // Parse if it's a string, otherwise use as is
      const contacts =
        typeof rawData === "string" ? JSON.parse(rawData) : rawData;

      res.json({ success: true, contacts: contacts || [] });
    } catch (err) {
      console.error("Fetch Emergency Contacts Error:", err);
      res
        .status(500)
        .json({ success: false, message: "Internal server error" });
    }
  },
);

router.delete("/terminate-account", async (req, res) => {
  const adminId = req.user.id;
  const userEmail = req.user.email;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1. Fetch estate details including e.name
    const estateResult = await client.query(
      `SELECT e.id, e.name, e.root_admin_email
       FROM estate_admin_users u
       JOIN estates e ON u.estate_id = e.id
       WHERE u.id = $1`,
      [adminId],
    );

    if (estateResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({
        success: false,
        message: "Estate not found or user not linked.",
      });
    }

    const {
      id: estateId,
      name: estateName,
      root_admin_email: rootAdminEmail,
    } = estateResult.rows[0];

    // 2. Case-insensitive comparison check for Root Admin Email
    if (
      !userEmail ||
      !rootAdminEmail ||
      userEmail.trim().toLowerCase() !== rootAdminEmail.trim().toLowerCase()
    ) {
      await client.query("ROLLBACK");
      return res.status(403).json({
        success: false,
        message:
          "Access Denied: Only the root admin email can terminate this account.",
      });
    }

    // 3. Create Super Admin notification snapshot
    const alertTitle = "Estate Account Terminated ⚠️";
    const alertMessage = `Estate "${estateName}" (ID: ${estateId}) has been permanently terminated by root admin ${userEmail}.`;

    const notifResult = await client.query(
      `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
       VALUES (NULL, NULL, 'super_admin', $1, $2, 'emergency')
       RETURNING *`,
      [alertTitle, alertMessage],
    );

    const superAdminNotification = notifResult.rows[0];

    // 4. Cascade delete associated records
    await client.query("DELETE FROM residents WHERE estate_id = $1", [
      estateId,
    ]);

    await client.query("DELETE FROM estate_admin_users WHERE estate_id = $1", [
      estateId,
    ]);

    await client.query("DELETE FROM estates WHERE id = $1", [estateId]);

    await client.query("COMMIT");

    // 5. Broadcast to superadmins room
    if (superAdminNotification) {
      io.to("superadmins").emit("new_notification", superAdminNotification);
    }

    res.clearCookie("token");

    return res.json({
      success: true,
      message: "Estate and all associated data have been permanently deleted.",
    });
  } catch (err) {
    await client.query("ROLLBACK").catch(() => {});
    console.error("Termination Error:", err);
    return res.status(500).json({
      success: false,
      message: "An error occurred during termination. Please contact support.",
    });
  } finally {
    client.release();
  }
});

router.post(
  "/notify-resident",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("manage_payment_items", "estate_administration"),
  async (req, res) => {
    const { estate_id, resident_id, title, message } = req.body;

    // Validate required payload parameters
    if (!resident_id || !title || !message) {
      return res.status(400).json({
        success: false,
        error: "Missing required fields: resident_id, title, or message",
      });
    }

    const client = await pool.connect();

    try {
      const userQuery = `
      SELECT id, push_token 
      FROM tenant_users 
      WHERE id = $1 AND $2 = ANY(estate_ids)
    `;
      const { rows: users } = await client.query(userQuery, [
        resident_id,
        estate_id,
      ]);

      if (users.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Resident not found for this estate",
        });
      }

      const resident = users[0];

      // 2. Insert the notification record into the DB
      const insertQuery = `
      INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
      VALUES ($1, $2, 'tenant', $3, $4, 'general')
      RETURNING *
    `;
      const { rows: dbRows } = await client.query(insertQuery, [
        estate_id,
        resident_id,
        title,
        message,
      ]);
      const notification = dbRows[0];

      if (io) {
        const roomName = `user_${resident_id}`;
        const sockets = await io.in(roomName).fetchSockets();
        console.log(`Sockets in ${roomName}:`, sockets.length);
        console.log("io to user:", `user_${resident_id}`);
        io.to(`user_${resident_id}`).emit("new_notification", notification);
      }

      // 4. Send push notification if push token exists
      if (resident.push_token) {
        const notificationData = {
          type: "notification",
          subtype: "general",
          user_id: resident_id,
          message: message,
        };

        await sendPushNotification(
          resident.push_token,
          title,
          message,
          notificationData,
        );
      }

      return res.status(200).json({
        success: true,
        data: notification,
      });
    } catch (err) {
      console.error("Error sending resident notification:", err);
      return res.status(500).json({
        success: false,
        error: "Internal server error",
      });
    } finally {
      client.release();
    }
  },
);

router.post(
  "/update-payment-items",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("manage_payment_items", "estate_administration"),
  async (req, res) => {
    const { estate_id, payment_items } = req.body;

    if (!estate_id || !Array.isArray(payment_items)) {
      return res.status(400).json({
        success: false,
        error:
          "Missing required fields: estate_id or valid payment_items array",
      });
    }

    // Clean strings and strip empty values
    const cleanedItems = payment_items
      .map((item) => (typeof item === "string" ? item.trim() : ""))
      .filter((item) => item.length > 0);

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Fetch state before update for audit trail
      const currentEstateRes = await client.query(
        `SELECT id, name, payment_items FROM estates WHERE id = $1`,
        [estate_id],
      );

      if (currentEstateRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          error: "Estate record not found",
        });
      }

      const estateBefore = currentEstateRes.rows[0];

      // 2. Perform bulk update replacing array
      const updateQuery = `
        UPDATE estates 
        SET payment_items = $2::text[]
        WHERE id = $1
        RETURNING id, name, payment_items;
      `;

      const { rows: updatedRows } = await client.query(updateQuery, [
        estate_id,
        cleanedItems,
      ]);
      const estateAfter = updatedRows[0];

      await client.query("COMMIT");

      // 3. Send response to client
      res.status(200).json({
        success: true,
        message: "Payment items list updated successfully",
        payment_items: estateAfter.payment_items,
      });

      // 4. Log audit entry asynchronously
      await createAppAuditLog(req, {
        estate_id,
        action_type: "ESTATE_PAYMENT_ITEMS_UPDATED",
        target_resource: "estates",
        target_id: estate_id,
        description: `Admin updated payment items for "${estateAfter.name}". Updated count: ${estateAfter.payment_items.length}`,
        state_before: { payment_items: estateBefore.payment_items || [] },
        state_after: { payment_items: estateAfter.payment_items },
        urgency: "MEDIUM",
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("Error updating payment items:", err);
      return res.status(500).json({
        success: false,
        error: "Internal server error execution block runtime crash.",
      });
    } finally {
      client.release();
    }
  },
);

export default router;
