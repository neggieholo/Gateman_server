import express from "express";
import multer from 'multer';
import path from 'path';
import pool from "./db.js";
import { v2 as cloudinary } from 'cloudinary';


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
      { folder: "estate_mate_kyc" },
      (error, result) => {
        if (error) return reject(error);
        resolve(result.secure_url);
      }
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

// -------------------- Approve Tenant --------------------
router.post("/approve-tenant/:joinRequestId", ensureAdmin, async (req, res) => {
  const { joinRequestId } = req.params;  // join_request id
  const admin = req.user;               // logged-in estate admin
  const estateId = admin.estate_id;     // estate to attach tenant to

  try {
    await pool.query("BEGIN");

    // 1️⃣ Fetch the join request (must exist and be pending)
    const jrRes = await pool.query(
      `SELECT * FROM join_requests WHERE id = $1 AND status = 'PENDING'`,
      [joinRequestId]
    );

    if (jrRes.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ error: "Join request not found or already processed" });
    }

    const joinRequest = jrRes.rows[0];

    // 2️⃣ Fetch the temp tenant linked to the join request
    const tempRes = await pool.query(
      `SELECT * FROM temp_tenant_users WHERE id = $1`,
      [joinRequest.temp_tenant_id]
    );

    if (tempRes.rows.length === 0) {
      await pool.query("ROLLBACK");
      return res.status(404).json({ error: "Temporary tenant not found" });
    }

    const temp = tempRes.rows[0];

    // 3️⃣ Insert into tenant_users using estate_id, block, unit from join_request
    const insertRes = await pool.query(
      `INSERT INTO tenant_users (estate_id, name, email, password, unit, block)
       VALUES ($1, $2, $3, $4, $5, $6)
       RETURNING *`,
      [
        estateId,
        temp.name,
        temp.email,
        temp.password,
        joinRequest.unit,
        joinRequest.block
      ]
    );

    const newTenant = insertRes.rows[0];

    // 4️⃣ Remove temp tenant record
    await pool.query(
      `DELETE FROM temp_tenant_users WHERE id = $1`,
      [temp.id]
    );

    // 5️⃣ Mark join request as approved
    await pool.query(
      `UPDATE join_requests SET status = 'APPROVED' WHERE id = $1`,
      [joinRequestId]
    );

    await pool.query("COMMIT");

    res.json({
      success: true,
      message: `${newTenant.name} added to estate`,
      tenant: newTenant
    });

  } catch (err) {
    await pool.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Fetch All Join Requests --------------------
router.get("/join-requests", ensureAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT jr.*, tt.name AS temp_tenant_name, tt.email AS temp_tenant_email
      FROM join_requests jr
      JOIN temp_tenant_users tt ON jr.temp_tenant_id = tt.id
      ORDER BY jr.requested_at DESC`
    );

    res.json({
      success: true,
      joinRequests: result.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Fetch All Tenants --------------------
router.get("/tenants", ensureAdmin, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT * FROM tenant_users ORDER BY created_at DESC`
    );

    res.json({
      success: true,
      tenants: result.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});


// -------------------- Delete Tenant --------------------
router.delete("/tenant/:id", ensureAdmin, async (req, res) => {
  const { id } = req.params; // tenant id

  try {
    const result = await pool.query(
      `DELETE FROM tenant_users WHERE id = $1 RETURNING *`,
      [id]
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

// -------------------- Delete Join Request --------------------
router.delete("/join-request/:id", ensureAdmin, async (req, res) => {
  const { id } = req.params; // join_request id

  try {
    const result = await pool.query(
      `DELETE FROM join_requests WHERE id = $1 RETURNING *`,
      [id]
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Join request not found" });
    }

    res.json({
      success: true,
      message: `Join request by temp tenant has been deleted`,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Create Join Request --------------------
router.post("/join-request", upload.fields([
  { name: 'selfie', maxCount: 1 },
  { name: 'idFront', maxCount: 1 },
  { name: 'idBack', maxCount: 1 },
  { name: 'utilityBill', maxCount: 1 }
]), async (req, res) => {
  const { tempTenantId, estateId, block, unit, idType } = req.body;
  
  if (!tempTenantId || !estateId) {
    return res.status(400).json({ error: "tempTenantId and estateId are required" });
  }

  try {
    // 1. Check for existing request in 'gateman' DB
    const existingReq = await pool.query(
      `SELECT id FROM join_requests WHERE temp_tenant_id = $1 AND estate_id = $2`,
      [tempTenantId, estateId]
    );

    if (existingReq.rows.length > 0) {
      return res.status(409).json({ success: false, error: "Duplicate request found." });
    }

    // 2. Upload available files to Cloudinary
    const uploadTasks = {};
    const fieldNames = ['selfie', 'idFront', 'idBack', 'utilityBill'];

    for (const field of fieldNames) {
      if (req.files[field]) {
        uploadTasks[field] = await uploadToCloudinary(req.files[field][0].buffer);
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
        uploadTasks['selfie'] || null,
        uploadTasks['idFront'] || null,
        uploadTasks['idBack'] || null,
        uploadTasks['utilityBill'] || null
      ]
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
});

router.get("/estates", async (req, res) => {
  try {
    const result = await pool.query("SELECT id, name, estate_code, created_at FROM estates ORDER BY name ASC");

    res.json({
      success: true,
      estates: result.rows,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});



export default router;

