import express from "express";
import pool from "./db.js";
import multer from "multer";
import { v2 as cloudinary } from "cloudinary";
import { isAuth } from "./middlewares.js";

const router = express.Router();

cloudinary.config({
  cloud_name: "diubaoqcr",
  api_key: "962197146245963",
  api_secret: process.env.CLOUDINARYAPISECRET,
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

// Reuse your Cloudinary logic
const uploadToCloudinary = (fileBuffer) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: "gateman_security_kyc" },
      (error, result) => {
        if (error) return reject(error);
        resolve(result.secure_url);
      },
    );
    uploadStream.end(fileBuffer);
  });
};

// Middleware to ensure the requester is an Estate Admin
const ensureAdmin = (req, res, next) => {
  if (req.isAuthenticated() && req.user.role === "ADMIN") {
    return next();
  }
  res.status(403).json({ error: "Unauthorized: Admin access required." });
};

// -------------------- 2. Fetch Security Requests (Admin View) --------------------
router.get("/join-requests", ensureAdmin, async (req, res) => {
  const estateId = req.user.estate_id;

  try {
    const result = await pool.query(
      `SELECT sjr.*, ts.name, ts.email, ts.phone
       FROM security_join_requests sjr
       JOIN temp_security_users ts ON sjr.temp_security_id = ts.id
       WHERE sjr.estate_id = $1 AND sjr.status = 'PENDING'
       ORDER BY sjr.requested_at DESC`,
      [estateId],
    );
    res.json({ success: true, requests: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- 1. Submit Security Join Request --------------------
router.post(
  "/join-request",
  upload.fields([
    { name: "selfie", maxCount: 1 },
    { name: "idFront", maxCount: 1 },
    { name: "idBack", maxCount: 1 },
  ]),
  async (req, res) => {
    const { tempSecurityId, estateId, idType } = req.body;
    // console.log("Received join request:", { tempSecurityId, estateId, idType });

    if (!tempSecurityId || !estateId) {
      return res
        .status(400)
        .json({ error: "Id and Estate registration are required" });
    }

    try {
      // Prevent duplicate requests
      const existing = await pool.query(
        "SELECT id FROM security_join_requests WHERE temp_security_id = $1",
        [tempSecurityId],
      );
      if (existing.rows.length > 0)
        return res.status(409).json({ error: "Request already pending." });

      const blockCheck = await pool.query(
        `SELECT id FROM estate_admin_users 
       WHERE estate_id = $1 AND $2 = ANY(blocked_security_ids)`,
        [estateId, tempSecurityId],
      );

      if (blockCheck.rows.length > 0) {
        return res.status(403).json({
          success: false,
          error:
            "Your application has been restricted by this estate's administration.",
        });
      }

      await pool.query(
        "UPDATE temp_security_users SET rejection_message = NULL, is_read = FALSE WHERE id = $1",
        [tempSecurityId],
      );

      // Upload Files
      const uploadTasks = {};
      const fieldNames = ["selfie", "idFront", "idBack"];
      for (const field of fieldNames) {
        if (req.files[field]) {
          uploadTasks[field] = await uploadToCloudinary(
            req.files[field][0].buffer,
          );
        }
      }

      const result = await pool.query(
        `INSERT INTO security_join_requests 
       (temp_security_id, estate_id, id_type, selfie_url, id_front_url, id_back_url)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
        [
          tempSecurityId,
          estateId,
          idType,
          uploadTasks["selfie"],
          uploadTasks["idFront"],
          uploadTasks["idBack"],
        ],
      );

      res.status(201).json({ success: true, joinRequest: result.rows[0] });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to submit security request." });
    }
  },
);

// -------------------- 3. Approve Security (The Promotion) --------------------
router.post("/approve/:requestId", ensureAdmin, async (req, res) => {
  const { requestId } = req.params;

  try {
    await pool.query("BEGIN");

    // 1. Get Request and User Info (Now including phone from temp table)
    const requestRes = await pool.query(
      `SELECT sjr.*, ts.name, ts.email, ts.password, ts.phone 
       FROM security_join_requests sjr 
       JOIN temp_security_users ts ON sjr.temp_security_id = ts.id 
       WHERE sjr.id = $1`,
      [requestId],
    );

    if (requestRes.rows.length === 0) throw new Error("Request not found");
    const data = requestRes.rows[0];

    // 2. Insert into permanent security_users (Added phone column and value)
    const insertRes = await pool.query(
      `INSERT INTO security_users 
       (estate_id, name, email, password, phone, avatar, id_type, id_front_url, id_back_url, role)
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'SECURITY') RETURNING id, name`,
      [
        data.estate_id,
        data.name,
        data.email,
        data.password,
        data.phone,
        data.selfie_url,
        data.id_type,
        data.id_front_url,
        data.id_back_url,
      ],
    );

    // 3. Cleanup Temp Records
    const feedbackObj = JSON.stringify({
      type: "approve",
      estate: data.estate_name,
      message: "Congratulations! You have been approved.",
    });

    await pool.query(
      "UPDATE temp_security_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
      [feedbackObj, data.temp_security_id],
    );

    await pool.query("DELETE FROM security_join_requests WHERE id = $1", [
      requestId,
    ]);

    await pool.query("COMMIT");
    res.json({
      success: true,
      message: `${insertRes.rows[0].name} is now an official guard.`,
    });
  } catch (err) {
    await pool.query("ROLLBACK");
    console.error("Promotion Error:", err);
    res.status(500).json({ error: "Promotion failed" });
  }
});

// -------------------- Decline Security Join Request --------------------
router.delete("/join-request/delete", ensureAdmin, async (req, res) => {
  const { id, message } = req.body;

  try {
    const infoRes = await pool.query(
      `SELECT sjr.temp_security_id, e.name as estate_name 
       FROM security_join_requests sjr 
       JOIN estates e ON sjr.estate_id = e.id 
       WHERE sjr.id = $1`,
      [id],
    );

    if (infoRes.rows.length === 0)
      return res.status(404).json({ error: "Request not found" });

    const { temp_security_id, estate_name } = infoRes.rows[0];

    const feedbackObj = JSON.stringify({
      type: "decline",
      estate: estate_name,
      message: message || "Your application was not approved at this time.",
    });

    await pool.query(
      "UPDATE temp_security_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
      [feedbackObj, temp_security_id],
    );

    await pool.query("DELETE FROM security_join_requests WHERE id = $1", [id]);

    res.json({ success: true, message: "Security request declined." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Block Security via Admin Table --------------------
router.put("/join-request/block", ensureAdmin, async (req, res) => {
  const { id, message } = req.body;
  const adminId = req.user.id;
  console.log("Block apihit for id:", id);

  try {
    const infoRes = await pool.query(
      `SELECT sjr.temp_security_id, e.name as estate_name 
       FROM security_join_requests sjr 
       JOIN estates e ON sjr.estate_id = e.id 
       WHERE sjr.id = $1`,
      [id],
    );

    if (infoRes.rows.length === 0)
      return res.status(404).json({ error: "Request not found" });

    const { temp_security_id, estate_name } = infoRes.rows[0];

    // 1. Add to Admin's Security Block List
    await pool.query(
      `UPDATE estate_admin_users 
       SET blocked_security_ids = array_append(blocked_security_ids, $1) 
       WHERE id = $2 AND NOT ($1 = ANY(blocked_security_ids))`,
      [temp_security_id, adminId],
    );

    const feedbackObj = JSON.stringify({
      type: "block",
      estate: estate_name,
      message: message || "You have been restricted from this estate.",
    });

    await pool.query(
      "UPDATE temp_security_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
      [feedbackObj, temp_security_id],
    );

    await pool.query("DELETE FROM security_join_requests WHERE id = $1", [id]);

    res.json({ success: true, message: "Security user blocked." });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Get Security Application Status --------------------
router.get("/my-request", async (req, res) => {
  const tempUserId = req.user.id;

  try {
    const activeRes = await pool.query(
      `SELECT sjr.*, e.name as estate_name 
       FROM security_join_requests sjr
       JOIN estates e ON sjr.estate_id = e.id
       WHERE sjr.temp_security_id = $1 AND sjr.status = 'PENDING'`,
      [tempUserId],
    );

    const userRes = await pool.query(
      "SELECT rejection_message, is_read FROM temp_security_users WHERE id = $1",
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

// -------------------- Dismiss Security Notification --------------------
router.delete("/notification/dismiss", async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const userId = req.user.id;
  const isTemp = req.user.isTemp;

  try {
    if (isTemp) {
      await pool.query(
        "UPDATE temp_security_users SET rejection_message = NULL WHERE id = $1",
        [userId],
      );
      return res.json({ success: true, message: "Notification dismissed" });
    }
    res.json({
      success: true,
      message: "Action not required for permanent security",
    });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Mark Security Notification as Read --------------------
router.put("/notification/read", async (req, res) => {
  const userId = req.user.id;
  if (req.user.isTemp) {
    await pool.query(
      "UPDATE temp_security_users SET is_read = TRUE WHERE id = $1",
      [userId],
    );
    return res.json({ success: true, message: "Notification marked as read" });
  }
  res.json({ success: true });
});

// -------------------- Fetch Blocked Guards --------------------
router.get("/blocked-users", ensureAdmin, async (req, res) => {
  const adminId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT id, name, email 
       FROM temp_security_users 
       WHERE id = ANY(
         SELECT unnest(blocked_security_ids) 
         FROM estate_admin_users 
         WHERE id = $1
       )`,
      [adminId],
    );

    res.json({ success: true, blockedUsers: result.rows });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Unblock Security --------------------
router.put("/join-request/unblock", ensureAdmin, async (req, res) => {
  const { tempSecurityId } = req.body;
  const adminId = req.user.id;

  try {
    await pool.query(
      `UPDATE estate_admin_users 
       SET blocked_security_ids = array_remove(blocked_security_ids, $1) 
       WHERE id = $2`,
      [tempSecurityId, adminId],
    );

    await pool.query(
      "UPDATE temp_security_users SET rejection_message = NULL WHERE id = $1",
      [tempSecurityId],
    );

    res.json({ success: true, message: "Security guard unblocked." });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Fetch All Security --------------------
router.get("/all", async (req, res) => {
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

    // If a Security Guard is fetching the list, hide their own record
    if (req.user.role === "SECURITY") {
      query = `
        SELECT id, name, email, phone, avatar, estate_id, push_token, 
               is_on_duty, last_checkin, last_checkout, checkin_location, checkout_location,last_known_location
        FROM security_users 
        WHERE estate_id = $1 AND id != $2
        ORDER BY name ASC`;
      params = [estateId, currentUserId];
    } else {
      // Admins see everyone
      query = `
        SELECT id, name, email, phone, avatar, estate_id, push_token, 
               is_on_duty, last_checkin, last_checkout, checkin_location, checkout_location ,last_known_location
        FROM security_users 
        WHERE estate_id = $1 
        ORDER BY name ASC`;
      params = [estateId];
    }

    const result = await pool.query(query, params);

    res.json({
      success: true,
      securityGuards: result.rows,
    });
  } catch (err) {
    console.error("Fetch security error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Delete Security Guard --------------------
router.delete("/delete/:id", ensureAdmin, async (req, res) => {
  const { id } = req.params;
  const admin_estate_id = req.user.estate_id;

  try {
    await pool.query("BEGIN");

    // 1. Get the Personnel details AND the Estate Name in one go
    // We join estates via the admin's estate_id to get the correct branding for the message
    const dataRes = await pool.query(
      `SELECT 
        u.name, u.email, u.password, u.phone, 
        e.name as estate_name
       FROM security_users u
       JOIN estates e ON e.id = $2
       WHERE u.id = $1`,
      [id, admin_estate_id],
    );

    if (dataRes.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res
        .status(404)
        .json({ error: "Personnel or Estate context not found" });
    }

    const { name, email, password, phone, estate_name } = dataRes.rows[0];

    // 2. Prepare the feedback object using the retrieved estate_name
    const feedbackObj = JSON.stringify({
      type: "decline",
      estate: estate_name,
      message: "Your personnel access has been revoked.",
    });

    // 3. Insert into temp_tenant_users (matching your specific schema)
    await pool.query(
      `INSERT INTO temp_security_users 
       (name, email, password, phone, rejection_message, is_read)
       VALUES ($1, $2, $3, $4, $5, FALSE)`,
      [name, email, password, phone, feedbackObj],
    );

    // 4. Delete the official record
    await pool.query("DELETE FROM security_users WHERE id = $1", [id]);

    await pool.query("COMMIT");
    res.json({
      success: true,
      message: `Personnel ${name} removed and notified via ${estate_name}.`,
    });
  } catch (err) {
    await pool.query("ROLLBACK");
    console.error("Removal Error:", err);
    res.status(500).json({ error: "Internal server error during removal" });
  }
});

// -------------------- Security Check-In/Out Action --------------------
router.post("/status-toggle", async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Unauthorized. Please log in." });
  }

  const { code, location } = req.body;
  const guardId = req.user.id;
  const estateId = req.user.estate_id;

  const locString = location
    ? `${location.latitude.toFixed(6)}, ${location.longitude.toFixed(6)}`
    : "Unknown";

  if (!code || code.length !== 10) {
    return res
      .status(400)
      .json({ success: false, error: "Security code must be 10 digits." });
  }

  try {
    await pool.query("BEGIN");

    const guardRes = await pool.query(
      "SELECT is_on_duty FROM security_users WHERE id = $1",
      [guardId],
    );

    if (guardRes.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ error: "Guard not found" });
    }

    const isOnDuty = guardRes.rows[0].is_on_duty;

    const adminCheck = await pool.query(
      "SELECT id FROM estate_admin_users WHERE estate_id = $1 AND security_checkin_code = $2",
      [estateId, code],
    );

    if (adminCheck.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res
        .status(401)
        .json({ error: "Invalid 10-digit code. Access denied." });
    }

    if (!isOnDuty) {
      // --- START SHIFT ---
      // Updates: Status, Checkin Location, Snapshot, AND last_checkin timestamp
      await pool.query(
        `UPDATE security_users 
         SET is_on_duty = TRUE, 
             checkin_location = $1,
             last_known_location = $2,
             last_location_time = CURRENT_TIMESTAMP,
             last_checkin = CURRENT_TIMESTAMP
         WHERE id = $3`,
        [locString, locString, guardId],
      );
    } else {
      // --- END SHIFT ---
      // Updates: Status, Checkout Location, Snapshot, AND last_checkout timestamp
      await pool.query(
        `UPDATE security_users 
         SET is_on_duty = FALSE, 
             checkout_location = $1,
             last_known_location = $2,
             last_location_time = CURRENT_TIMESTAMP,
             last_checkout = CURRENT_TIMESTAMP
         WHERE id = $3`,
        [locString, locString, guardId],
      );
    }

    await pool.query("COMMIT");
    res.json({ success: true, isOnDuty: !isOnDuty });
  } catch (err) {
    await pool.query("ROLLBACK").catch(() => {});
    console.error("Toggle Error:", err);
    res.status(500).json({ error: "Failed to toggle duty status." });
  }
});

// -------------------- Fetch Security Duty Logs --------------------
router.get("/logs", ensureAdmin, async (req, res) => {
  const estateId = req.user.estate_id;

  try {
    const result = await pool.query(
      `SELECT 
        sl.id, 
        sl.checkin_time, 
        sl.checkout_time, 
        sl.checkin_location, 
        sl.checkout_location,
        s.name AS guard_name
       FROM security_logs sl
       JOIN security_users s ON sl.security_id = s.id
       WHERE s.estate_id = $1
       ORDER BY s.name ASC, sl.checkin_time DESC`,
      [estateId],
    );

    res.json({
      success: true,
      logs: result.rows,
    });
  } catch (err) {
    console.error("Fetch Security Logs Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Generate & Save 10-Digit Security Code --------------------
router.put("/generate-checkin-code", ensureAdmin, async (req, res) => {
  const adminId = req.user.id;

  try {
    // Generate a random 10-digit numeric string
    let newCode = "";
    for (let i = 0; i < 10; i++) {
      newCode += Math.floor(Math.random() * 10).toString();
    }

    // Update the admin's record
    const result = await pool.query(
      `UPDATE estate_admin_users 
       SET security_checkin_code = $1 
       WHERE id = $2 
       RETURNING security_checkin_code`,
      [newCode, adminId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Admin not found." });
    }

    res.json({
      success: true,
      code: result.rows[0].security_checkin_code,
      message: "New 10-digit security code generated successfully.",
    });
  } catch (err) {
    console.error("Error generating code:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Fetch Existing 10-Digit Security Code --------------------
router.get("/get-checkin-code", ensureAdmin, async (req, res) => {
  const adminId = req.user.id;

  try {
    const result = await pool.query(
      `SELECT security_checkin_code FROM estate_admin_users WHERE id = $1`,
      [adminId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Admin not found." });
    }

    res.json({
      success: true,
      code: result.rows[0].security_checkin_code,
    });
  } catch (err) {
    console.error("Error fetching code:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.post("/update-location", async (req, res) => {
  if (
    !req.isAuthenticated ||
    !req.isAuthenticated() ||
    req.user.role !== "SECURITY"
  ) {
    return res
      .status(401)
      .json({ error: "Unauthorized: Security personnel only." });
  }
  const { latitude, longitude } = req.body;
  const userId = req.user.id;

  if (!latitude || !longitude) {
    return res.status(400).json({ error: "Coordinates required" });
  }

  try {
    const locationString = `${latitude.toFixed(6)}, ${longitude.toFixed(6)}`;

    // Updated to use 'last_known_location' and 'last_location_time'
    await pool.query(
      `UPDATE security_users 
       SET last_known_location = $1, 
           last_location_time = CURRENT_TIMESTAMP 
       WHERE id = $2`,
      [locationString, userId],
    );

    res.json({ success: true, message: "Location synchronized" });
  } catch (err) {
    console.error("Location Update Error:", err);
    res.status(500).json({ error: "Failed to update location" });
  }
});

// -------------------- Update Security Push Token --------------------
router.post("/update-push-token", async (req, res) => {
  const userId = req.user?.id;
  const role = req.user?.role;
  const { pushToken } = req.body;

  if (!userId || role !== "SECURITY") {
    return res.status(401).json({
      error: "Unauthorized: Only security personnel can update tokens here.",
    });
  }

  if (!pushToken) {
    return res.status(400).json({ error: "pushToken is required" });
  }

  try {
    const result = await pool.query(
      `UPDATE security_users 
       SET push_token = $1 
       WHERE id = $2 
       RETURNING id, name`,
      [pushToken, userId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Security record not found" });
    }

    console.log(`[Push Token] Updated for Guard: ${result.rows[0].name}`);

    res.json({
      success: true,
      message: "Security push token synchronized",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("Security Push Token Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Submit a Report (Resident/User) --------------------
router.post("/report", isAuth, async (req, res) => {
  const {
    type,
    category,
    subject,
    description,
    payment_id,
    target_security_ids,
  } = req.body;

  const estate_id = req.user?.estate_id;
  const reporter_id = req.user?.id;

  try {
    const query = `
      INSERT INTO estate_reports 
      (estate_id, reporter_id, type, category, subject, description, linked_payment_id, target_security_ids)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      RETURNING *`;

    const result = await pool.query(query, [
      estate_id,
      reporter_id,
      type,
      category,
      subject,
      description,
      payment_id || null, // Handles non-payment reports gracefully
      target_security_ids || [],
    ]);

    res.status(201).json({ success: true, report: result.rows[0] });
  } catch (err) {
    console.error("DB Error:", err.message);
    res.status(500).json({ error: "Failed to submit report" });
  }
});

// -------------------- Fetch Reports (Admin View) --------------------
router.get("/report", ensureAdmin, async (req, res) => {
  const estateId = req.user.estate_id;
  // console.log(`Fetching reports for estate_id: ${estateId} by admin_id: ${req.user.id}`);

  try {
    const result = await pool.query(
      `SELECT r.*, u.name as reporter_name 
       FROM estate_reports r
       JOIN tenant_users u ON r.reporter_id = u.id
       WHERE r.estate_id = $1
       ORDER BY r.created_at DESC`,
      [estateId]
    );
    
    console.log(`Fetched ${result.rows.length} reports for estate_id: ${estateId}`);
    res.json({ success: true, reports: result.rows });
  } catch (err) {
    console.error("Fetch Reports Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// GET /my-reports - Fetch reports submitted by the logged-in resident
router.get("/my-reports", isAuth, async (req, res) => {
  const reporterId = req.user.id;
  const estateId = req.user.estate_id;

  try {
    const result = await pool.query(
      `SELECT * FROM estate_reports 
       WHERE reporter_id = $1 AND estate_id = $2
       ORDER BY created_at DESC`,
      [reporterId, estateId]
    );

    console.log(`Fetched ${result.rows.length} personal reports for user_id: ${reporterId}`);
    
    res.json({ 
      success: true, 
      reports: result.rows 
    });
  } catch (err) {
    console.error("Fetch My Reports Error:", err);
    res.status(500).json({ 
      success: false, 
      error: "Internal server error" 
    });
  }
});

// -------------------- Update Report Status --------------------
router.patch("/report/status/:id", ensureAdmin, async (req, res) => {
  const { id } = req.params;
  const { status, admin_response } = req.body; // Destructure the new field
  const estate_id = req.user.estate_id;

  try {
    const result = await pool.query(
      `UPDATE estate_reports 
       SET status = $1, 
           admin_response = $2
       WHERE id = $3 AND estate_id = $4 
       RETURNING *`,
      [status, admin_response || null, id, estate_id],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Report not found" });
    }

    res.json({ success: true, report: result.rows[0] });
  } catch (err) {
    console.error("Database Error:", err);
    res.status(500).json({ error: "Failed to update status and response" });
  }
});

// -------------------- Delete Report (Resident Only) --------------------
router.delete("/:id", async (req, res) => {
  const { id } = req.params;
  const userId = req.user.id; 

  try {
    const result = await pool.query(
      "DELETE FROM estate_reports WHERE id = $1 AND reporter_id = $2 RETURNING id",
      [id, userId]
    );

    if (result.rows.length === 0) {
      return res.status(403).json({ 
        error: "Unauthorized: You can only delete your own reports." 
      });
    }
    
    res.json({ success: true, message: "Report deleted." });
  } catch (err) {
    res.status(500).json({ error: "Failed to delete report" });
  }
});

router.delete("/my-reports/:id", isAuth, async (req, res) => {
  try {
    const { id } = req.params;
    // ensure the report belongs to this user
    const result = await pool.query(
      "DELETE FROM estate_reports WHERE id = $1 AND reporter_id = $2 RETURNING *",
      [id, req.user.id],
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ success: false, error: "Report not found" });
    }

    res.json({ success: true, message: "Deleted successfully" });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
