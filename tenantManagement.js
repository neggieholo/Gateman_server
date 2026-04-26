import express from "express";
import multer from "multer";
import pool from "./db.js";
import { v2 as cloudinary } from "cloudinary";
import { isAuth } from "./middlewares.js";
import { sendRegistrationOTP } from "./emailService.js";
import crypto from "crypto";

const router = express.Router();

cloudinary.config({
  cloud_name: "diubaoqcr",
  api_key: "962197146245963",
  api_secret: process.env.CLOUDINARYAPISECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

const uploadToCloudinary = (fileBuffer) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: "gateman_tenant_kyc" },
      (error, result) => {
        if (error) return reject(error);
        resolve(result.secure_url);
      },
    );
    uploadStream.end(fileBuffer);
  });
};

const ensureAdmin = (req, res, next) => {
  if (!req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  // Assuming admin users do NOT have a 'unit' property
  if (req.user.unit) {
    return res.status(403).json({ error: "Not authorized" });
  }

  // User is an admin → allow access
  next();
};

export const ensureTempTenant = (req, res, next) => {
  if (req.isAuthenticated()) {
    return next();
  }
  console.log("Unauthorized access attempt to temp tenant route");
  res.status(401).json({ error: "Unauthorized" });
};

// -------------------- Fetch All Join Requests --------------------
router.get("/join-requests", ensureAdmin, async (req, res) => {
  const adminId = req.user.id; // Get the ID of the logged-in admin

  try {
    const result = await pool.query(
      `SELECT jr.*, tt.name AS temp_tenant_name, tt.email AS temp_tenant_email, tt.phone AS temp_tenant_phone
       FROM join_requests jr
       JOIN temp_tenant_users tt ON jr.temp_tenant_id = tt.id
       JOIN estate_admin_users eau ON jr.estate_id = eau.estate_id
       WHERE eau.id = $1
       ORDER BY jr.requested_at DESC`,
      [adminId],
    );

    res.json({
      success: true,
      joinRequests: result.rows,
    });
  } catch (err) {
    console.error("Fetch Join Requests Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Fetch All Tenants --------------------
router.get("/tenants", async (req, res) => {
  try {
    const estateId = req.user?.estate_id;
    const currentUserId = req.user?.id;

    if (!estateId) {
      return res
        .status(401)
        .json({ error: "Unauthorized: No estate assigned." });
    }
    let query;
    let params;

    if (req.user.unit) {
      query = `
        SELECT id, name, email, unit, block, avatar, estate_id, push_token
        FROM tenant_users 
        WHERE estate_id = $1 AND id != $2
        ORDER BY name ASC`;
      params = [estateId, currentUserId];
    } else {
      query = `
        SELECT id, name, email, unit, block, avatar, estate_id, push_token 
        FROM tenant_users 
        WHERE estate_id = $1 
        ORDER BY name ASC`;
      params = [estateId];
    }

    const result = await pool.query(query, params);

    res.json({
      success: true,
      tenants: result.rows,
    });
  } catch (err) {
    console.error("Fetch tenants error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Delete Tenant --------------------
router.delete("/tenant/:id", ensureAdmin, async (req, res) => {
  const { id } = req.params; // tenant id

  try {
    const result = await pool.query(
      `DELETE FROM tenant_users WHERE id = $1 RETURNING *`,
      [id],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Tenant not found" });
    }

    res.json({
      success: true,
      message: `${result.rows[0].name} has been deleted from tenants`,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Create Join Request --------------------
router.post(
  "/join-request",
  upload.fields([
    { name: "selfie", maxCount: 1 },
    { name: "idFront", maxCount: 1 },
    { name: "idBack", maxCount: 1 },
    { name: "utilityBill", maxCount: 1 },
  ]),
  async (req, res) => {
    const { tempTenantId, estateId, block, unit, idType } = req.body;

    if (!tempTenantId || !estateId) {
      return res
        .status(400)
        .json({ error: "Id and Estate registration are required" });
    }

    try {
      const existingReq = await pool.query(
        `SELECT id FROM join_requests WHERE temp_tenant_id = $1`,
        [tempTenantId],
      );

      if (existingReq.rows.length > 0) {
        return res
          .status(409)
          .json({
            success: false,
            error: "Only one join request is allowed pending approval.",
          });
      }

      const blockCheck = await pool.query(
        `SELECT id FROM estate_admin_users 
     WHERE estate_id = $1 AND $2 = ANY(blocked_tenant_ids)`,
        [estateId, tempTenantId],
      );

      if (blockCheck.rows.length > 0) {
        return res.status(403).json({
          success: false,
          error:
            "Your account has been restricted by this estate's administration.",
        });
      }

      await pool.query(
        "UPDATE temp_tenant_users SET rejection_message = NULL, is_read = FALSE WHERE id = $1",
        [tempTenantId],
      );

      const uploadTasks = {};
      const fieldNames = ["selfie", "idFront", "idBack", "utilityBill"];

      for (const field of fieldNames) {
        if (req.files[field]) {
          uploadTasks[field] = await uploadToCloudinary(
            req.files[field][0].buffer,
          );
        }
      }

      // 3. Insert into PostgreSQL using the secure Cloudinary URLs
      const result = await pool.query(
        `INSERT INTO join_requests 
       (temp_tenant_id, estate_id, block, unit, id_type, selfie_url, id_front_url, id_back_url, utility_bill_url)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
       RETURNING *`,
        [
          tempTenantId,
          estateId,
          block || null,
          unit || null,
          idType || null,
          uploadTasks["selfie"] || null,
          uploadTasks["idFront"] || null,
          uploadTasks["idBack"] || null,
          uploadTasks["utilityBill"] || null,
        ],
      );

      res.status(201).json({
        success: true,
        message: "Join request submitted with Cloudinary storage",
        joinRequest: result.rows[0],
      });
    } catch (err) {
      console.error("KYC Upload Error:", err);
      res.status(500).json({ error: "Internal server error during upload" });
    }
  },
);

// -------------------- Approve Tenant --------------------
router.post("/approve-tenant/:joinRequestId", ensureAdmin, async (req, res) => {
  const { joinRequestId } = req.params;
  const admin = req.user;
  const estateId = admin.estate_id;

  try {
    await pool.query("BEGIN");

    // 1. Fetch the join request with all KYC document URLs
    const jrRes = await pool.query(
      `SELECT * FROM join_requests WHERE id = $1 AND status = 'PENDING'`,
      [joinRequestId],
    );

    if (jrRes.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res
        .status(404)
        .json({ error: "Join request not found or processed" });
    }

    const joinRequest = jrRes.rows[0];

    // 2. Fetch the temporary tenant
    const tempRes = await pool.query(
      `SELECT * FROM temp_tenant_users WHERE id = $1`,
      [joinRequest.temp_tenant_id],
    );

    if (tempRes.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ error: "Temporary tenant not found" });
    }

    const temp = tempRes.rows[0];

    // 3. Promote to permanent tenant_users with full KYC data
    const insertRes = await pool.query(
      `INSERT INTO tenant_users (
        estate_id, name, email, password,phone, unit, block, 
        avatar, id_type, id_front_url, id_back_url, utility_bill_url,
        first_login, role
      )
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11,$12,$13,$14)
       RETURNING *`,
      [
        estateId,
        temp.name,
        temp.email,
        temp.password,
        temp.phone,
        joinRequest.unit,
        joinRequest.block,
        joinRequest.selfie_url,
        joinRequest.id_type,
        joinRequest.id_front_url,
        joinRequest.id_back_url,
        joinRequest.utility_bill_url,
        true,
        "TENANT",
      ],
    );

    const newTenant = insertRes.rows[0];

    // 4. CLEANUP: Remove temp records
    const feedbackObj = JSON.stringify({
      type: "approve",
      estate: joinRequest.estate_name,
      message:
        "Your residency has been approved! Please log out and log back in to access the tenant dashboard.",
    });

    await pool.query(
      "UPDATE temp_tenant_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
      [feedbackObj, temp.id],
    );

    await pool.query("DELETE FROM join_requests WHERE id = $1", [
      joinRequestId,
    ]);

    await pool.query("COMMIT");

    res.json({
      success: true,
      message: `${newTenant.name} has been verified and fully promoted.`,
      tenant: newTenant,
    });
  } catch (err) {
    await pool.query("ROLLBACK");
    console.error("Approval Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Delete Join Request --------------------
router.delete("/join-request/delete", ensureAdmin, async (req, res) => {
  const { id, message } = req.body;

  try {
    const infoRes = await pool.query(
      `SELECT jr.temp_tenant_id, e.name as estate_name 
       FROM join_requests jr 
       JOIN estates e ON jr.estate_id = e.id 
       WHERE jr.id = $1`,
      [id],
    );

    if (infoRes.rows.length === 0)
      return res.status(404).json({ error: "Request not found" });

    const { temp_tenant_id, estate_name } = infoRes.rows[0];

    // Construct structured feedback
    const feedbackObj = JSON.stringify({
      type: "decline",
      estate: estate_name,
      message: message || "",
    });

    await pool.query(
      "UPDATE temp_tenant_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
      [feedbackObj, temp_tenant_id],
    );

    await pool.query("DELETE FROM join_requests WHERE id = $1", [id]);

    res.json({ success: true, message: "Request declined and user notified." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Block Tenant via Admin Table --------------------
router.put("/join-request/block", ensureAdmin, async (req, res) => {
  const { id, message } = req.body;
  const adminId = req.user.id;

  try {
    const infoRes = await pool.query(
      `SELECT jr.temp_tenant_id, e.name as estate_name 
       FROM join_requests jr 
       JOIN estates e ON jr.estate_id = e.id 
       WHERE jr.id = $1`,
      [id],
    );

    if (infoRes.rows.length === 0)
      return res.status(404).json({ error: "Request not found" });

    const { temp_tenant_id, estate_name } = infoRes.rows[0];

    // 1. Add to Admin's Block List
    await pool.query(
      `UPDATE estate_admin_users 
       SET blocked_tenant_ids = array_append(blocked_tenant_ids, $1) 
       WHERE id = $2 AND NOT ($1 = ANY(blocked_tenant_ids))`,
      [temp_tenant_id, adminId],
    );

    // 2. Set structured feedback as 'block'
    const feedbackObj = JSON.stringify({
      type: "block",
      estate: estate_name,
      message: message || "You have been restricted from this estate.",
    });

    await pool.query(
      "UPDATE temp_tenant_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
      [feedbackObj, temp_tenant_id],
    );

    await pool.query("DELETE FROM join_requests WHERE id = $1", [id]);

    res.json({ success: true, message: "User blocked and request removed." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/my-request", ensureTempTenant, async (req, res) => {
  const tempUserId = req.user.id;

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

// -------------------- Fetch Blocked Users (Optimized) --------------------
router.get("/blocked-users", ensureAdmin, async (req, res) => {
  const adminId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT id, name, email 
       FROM temp_tenant_users 
       WHERE id = ANY(
         SELECT unnest(blocked_tenant_ids) 
         FROM estate_admin_users 
         WHERE id = $1
       )`,
      [adminId],
    );

    res.json({
      success: true,
      blockedUsers: result.rows,
    });
  } catch (err) {
    console.error("Fetch Blocked Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.put("/join-request/unblock", ensureAdmin, async (req, res) => {
  const { tempTenantId } = req.body;
  const adminId = req.user.id;

  try {
    // Remove the specific ID from the blocked_tenant_ids array
    await pool.query(
      `UPDATE estate_admin_users 
       SET blocked_tenant_ids = array_remove(blocked_tenant_ids, $1) 
       WHERE id = $2`,
      [tempTenantId, adminId],
    );

    // Optional: Clear the 'block' message for the user so they can try again
    await pool.query(
      "UPDATE temp_tenant_users SET rejection_message = NULL WHERE id = $1",
      [tempTenantId],
    );

    res.json({ success: true, message: "User has been unblocked." });
  } catch (err) {
    console.error("Unblock Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get("/estates", async (req, res) => {
  // if (!req.user) {
  //   return res.status(401).json({ error: "Not authenticated" });
  // }
  try {
    // Joining estates with estate_admin_users to get city and town
    const query = `
      SELECT 
        id, 
        name, 
        estate_code, 
        created_at,
        city,
        town
      FROM estates 
      ORDER BY e.name ASC
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

router.post("/set-payment-info", isAuth, async (req, res) => {
  const { bankName, accountName, accountNumber, utilityInstructions } =
    req.body;
  const estateId = req.user.estateId;

  await pool.query(
    `UPDATE estates SET 
      bank_name = $1, 
      bank_account_name = $2, 
      bank_account_number = $3,
      payment_instructions = $4
     WHERE id = $5`,
    [bankName, accountName, accountNumber, utilityInstructions, estateId],
  );
  res.json({ success: true, message: "Payment details updated." });
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
  console.log("profile otp api hit");
  const { target, type } = req.body;
  const adminId = req.user.id;
  const normalizedTarget = target.trim();
  console.log("Generated Normalized Target:", normalizedTarget);

  const checkUser = await pool.query(
    `SELECT id FROM estate_admin_users 
       WHERE (email = $1 OR phone_number = $1) 
       AND id != $2`,
    [target, adminId],
  );

  if (checkUser.rows.length > 0) {
    return res.status(400).json({
      success: false,
      message: `This ${type} is already registered to another account.`,
    });
  }
  const OTP_SECRET = process.env.OTP_SECRET;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
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
  const normalizedTarget = target.trim();
  console.log("Generated Normalized Target:", normalizedTarget);

  const checkUser = await pool.query(
    `SELECT id FROM tenant_users 
       WHERE (email = $1 OR phone = $1) 
       AND id != $2`,
    [target, tenantId],
  );

  if (checkUser.rows.length > 0) {
    return res.status(400).json({
      success: false,
      message: `This ${type} is already registered to another account.`,
    });
  }
  const OTP_SECRET = process.env.OTP_SECRET;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
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

router.post("/verify-otp-only", async (req, res) => {
  const { otp, metadata, target } = req.body;

  console.log("Verifying OTP with metadata:", metadata, "and target:", target);
  try {
    // 1. Normalize the target (Remove spaces and lowercase email)
    const normalizedTarget = target.trim();
    console.log("Normalized Target for OTP Verification:", normalizedTarget);

    const [hash, expires] = metadata.split(".");
    console.log("Extracted Hash:", hash);
    console.log("Extracted Expires:", expires);

    if (Date.now() > parseInt(expires)) {
      return res.status(400).json({ error: "OTP expired. Please resend." });
    }

    // 3. Re-create the hash using the EXACT same format as the send route
    const data = `${normalizedTarget}.${otp}.${expires}`;
    console.log("Data for OTP Hash Verification:", data);
    const verifyHash = crypto
      .createHmac("sha256", process.env.OTP_SECRET)
      .update(data)
      .digest("hex");
    console.log("Recreated Hash for Verification:", verifyHash);

    if (verifyHash !== hash) {
      return res.json({ success: false, message: "Invalid OTP code." });
    }

    res.json({ success: true });
  } catch (err) {
    console.error("Verification Error:", err);
    res.status(500).json({ success: false, message: "Server error" });
  }
});

router.post("/tenant/update-config", isAuth, async (req, res) => {
  console.log("Update tenant profile api hit");
  const { email, phone } = req.body;
  const userId = req.user.id;
  const isTemp = req.user.isTemp === true; 
  console.log(`Updating profile for user ${userId} (Temp: ${isTemp}) with email: ${email} and phone: ${phone}`);

  // Determine which table to target
  const tableName = isTemp ? "temp_tenant_users" : "tenant_users";

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // We only allow residents to update email and phone.
    // Name, Block, and Unit are usually locked after verification for security.
    const updateQuery = `
      UPDATE ${tableName} 
      SET email = $1, phone = $2 
      WHERE id = $3 
      RETURNING *`;

    const values = [email.trim(), phone.trim(), userId];

    const result = await client.query(updateQuery, values);

    if (result.rowCount === 0) {
      throw new Error("User not found");
    }

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
    console.error("Resident Update Error:", err);

    // Handle unique constraint violations (e.g., email already exists)
    if (err.code === "23505") {
      return res.status(400).json({
        success: false,
        message: "Email or Phone number is already in use by another resident.",
      });
    }

    res.status(500).json({ success: false, message: "Internal server error" });
  } finally {
    client.release();
  }
});

// -------------------- Update Estate Configuration --------------------
router.post("/update-config", ensureAdmin, async (req, res) => {
  const { config } = req.body;
  const adminId = req.user.id;
  const estateId = req.user.estate_id;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const adminQuery = `
      UPDATE estate_admin_users 
      SET name = $1, email = $2, phone_number = $3 
      WHERE id = $4 
      RETURNING *`;
    const adminValues = [
      config.admin_name,
      config.email,
      config.phone_number,
      adminId,
    ];
    const adminResult = await client.query(adminQuery, adminValues);

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
    res.status(500).json({ success: false, message: "Internal server error" });
  } finally {
    client.release();
  }
});

router.delete("/terminate-account", isAuth, async (req, res) => {
  const adminId = req.user.id; // Extracted from JWT
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1. Get the Estate ID associated with this admin
    const estateResult = await client.query(
      "SELECT estate_id FROM estate_admin_users WHERE id = $1",
      [adminId],
    );

    if (estateResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res
        .status(404)
        .json({ success: false, message: "Estate not found." });
    }

    const estateId = estateResult.rows[0].estate_id;

    // 2. Delete all residents associated with this estate
    await client.query("DELETE FROM residents WHERE estate_id = $1", [
      estateId,
    ]);

    // 4. Delete the admin user(s)
    await client.query("DELETE FROM estate_admin_users WHERE estate_id = $1", [
      estateId,
    ]);

    // 5. Finally, delete the estate record itself
    await client.query("DELETE FROM estates WHERE id = $1", [estateId]);

    await client.query("COMMIT");

    // Optional: Clear cookies if using session-based auth
    res.clearCookie("token");

    res.json({
      success: true,
      message: "Estate and all associated data have been permanently deleted.",
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Termination Error:", err);
    res.status(500).json({
      success: false,
      message: "An error occurred during termination. Please contact support.",
    });
  } finally {
    client.release();
  }
});

export default router;
