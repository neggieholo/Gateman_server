import express from "express";
import bcrypt from "bcrypt";
import axios from "axios";
import pool from "./db.js";
import crypto from "crypto";
import { isAuth } from "./middlewares.js";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    const { name, email, password, state, lga, otp, metadata } = req.body;
    const OTP_SECRET = process.env.OTP_SECRET;

    if (!name || !email || !password) {
      return res
        .status(400)
        .json({ error: "Name, email, and password are required" });
    }

    const [hash, expires] = metadata.split(".");

    if (Date.now() > parseInt(expires)) {
      return res.status(400).json({ error: "OTP expired. Please resend." });
    }

    const data = `${email}.${otp}.${expires}`;
    const verifyHash = crypto
      .createHmac("sha256", OTP_SECRET)
      .update(data)
      .digest("hex");

    if (
      !crypto.timingSafeEqual(
        Buffer.from(verifyHash, "hex"),
        Buffer.from(hash, "hex"),
      )
    ) {
      return res.status(400).json({ error: "Invalid OTP code." });
    }

    const emailCheck = await pool.query(
      `SELECT email FROM estate_admin_users WHERE email = $1`,
      [email],
    );

    if (emailCheck.rows.length > 0) {
      return res
        .status(400)
        .json({ error: "This email is already an active administrator." });
    }

    const estateCheck = await pool.query(
      `SELECT id FROM estates
             WHERE LOWER(name) = LOWER($1) AND LOWER(state) = LOWER($2) AND LOWER(lga) = LOWER($3)`,
      [name, state, lga],
    );

    if (estateCheck.rows.length > 0) {
      return res.status(400).json({
        error: "An estate with this name already exists in this location.",
      });
    }

    const amount = 1000 * 50;
    const reference = `${email.replace("@", "-")}_${Date.now()}`;

    // Initiate payment
    const paymentData = {
      email,
      amount,
      reference,
      callback_url:
        "https://0a2e-102-88-55-201.ngrok-free.app/api/payment/callback",
      metadata: { name, state, lga },
    };

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      paymentData,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      },
    );

    const hashedPassword = await bcrypt.hash(password, 10);

    await pool.query(
      `INSERT INTO temp_payment_info (tx_ref, name, email, password, state, lga) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
      [reference, name, email, hashedPassword, state, lga],
    );

    res.json({ paymentLink: response.data.data.authorization_url });
  } catch (error) {
    console.error(
      "Paystack Init Error:",
      error.response?.data || error.message,
    );
    res.status(500).json({ error: "Payment initialization failed" });
  }
});

router.post("/paystack-webhook", async (req, res) => {
  console.log("webhook hit!");
  const secret = process.env.PAYSTACK_SECRET_KEY;

  const hash = crypto
    .createHmac("sha512", secret)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (hash !== req.headers["x-paystack-signature"]) {
    return res.sendStatus(400);
  }

  const event = req.body;
  if (event.event !== "charge.success") {
    return res.sendStatus(200);
  }

  const { reference } = event.data;

  const client = await pool.connect();
  try {
    const tempUserResult = await client.query(
      "SELECT * FROM temp_payment_info WHERE tx_ref = $1",
      [reference],
    );

    if (tempUserResult.rows.length === 0) return res.sendStatus(200);

    const tempUser = tempUserResult.rows[0];

    await client.query("BEGIN");

    // Create Estate
    const estateCode = crypto.randomBytes(3).toString("hex").toUpperCase();
    const estateResult = await client.query(
      "INSERT INTO estates (name, estate_code, state,lga ) VALUES ($1, $2, $3, $4) RETURNING id",
      [`${tempUser.name} Estate`, estateCode, tempUser.state, tempUser.lga],
    );
    const estateId = estateResult.rows[0].id;

    // Subscription expiry
    const subscriptionExpiry = new Date();
    subscriptionExpiry.setFullYear(subscriptionExpiry.getFullYear() + 1);

    // Insert into estate_admin_users with city/town
    await client.query(
      `INSERT INTO estate_admin_users 
       (estate_id, email, password, subscription_expiry, role) 
       VALUES ($1, $2, $3, $4, $5)`,
      [
        estateId,
        tempUser.email,
        tempUser.password,
        subscriptionExpiry,
        "ADMIN",
      ],
    );

    // Delete temp record
    await client.query("DELETE FROM temp_payment_info WHERE tx_ref = $1", [
      reference,
    ]);

    // Commit
    await client.query("COMMIT");

    console.log(`✅ Estate and admin user created for ${tempUser.email}`);
    res.sendStatus(200);
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Webhook transaction error:", error); // log full error
    res.status(500).json({ error: "Internal server error" });
  } finally {
    client.release();
  }
});

router.get("/callback", async (req, res) => {
  const reference = req.query.reference;

  try {
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      },
    );

    if (response.data.data.status === "success") {
      res.redirect(`http://localhost:3005/payment-success?ref=${reference}`);
    } else {
      res.redirect(`http://localhost:3005/payment-failure`);
    }
  } catch (err) {
    console.error("Verification Error:", err.response?.data || err.message);
    res.redirect(`http://localhost:3005/payment-failure`);
  }
});

// POST: Upload Payment Log
router.post("/upload", isAuth, async (req, res) => {
  const {
    amount,
    category,
    transaction_reference,
    receipt_url,
    notes,
    resident_name,
    payment_date,
    payment_type, 
  } = req.body;

  const { id: resident_id, estate_id } = req.user;

  console.log("Received payment log upload paymentdate:", payment_date);
  try {
    const query = `
      INSERT INTO payment_logs 
      (resident_id, estate_id, amount, category, transaction_reference, receipt_url, notes, resident_name, payment_date, payment_type, status) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending') 
      RETURNING *`;

    const result = await pool.query(query, [
      resident_id,
      estate_id,
      amount,
      category,
      transaction_reference,
      receipt_url,
      notes,
      resident_name,
      new Date(payment_date),
      payment_type,
    ]);

    res.status(201).json({ success: true, data: result.rows[0] });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

// GET: Fetch History with Date Filtering
router.get("/history", isAuth, async (req, res) => {
  const { startDate, endDate } = req.query; 
  console.log("Fetching history with filters:", { startDate, endDate });
  const { id: resident_id, estate_id } = req.user;

  try {
    let query = `SELECT * FROM payment_logs WHERE resident_id = $1 AND estate_id = $2`;
    const params = [resident_id, estate_id];

    if (startDate && endDate) {
      query += ` AND payment_date::DATE BETWEEN $3 AND $4`;
      params.push(startDate, endDate);
    }

    query += ` ORDER BY created_at DESC`;

    const result = await pool.query(query, params);
    res.json({ success: true, history: result.rows });
  } catch (error) {
    res.status(500).json({ success: false, error: "Failed to fetch history" });
  }
});

// DELETE: Remove a log (only if still pending)
router.delete("/delete/:id", isAuth, async (req, res) => {
  try {
    console.log(`Attempting to delete log ID ${req.params.id} for resident ID ${req.user.id}`);
    const query = `DELETE FROM payment_logs WHERE id = $1 AND resident_id = $2 AND status = 'pending' RETURNING *`;
    const result = await pool.query(query, [req.params.id, req.user.id]);

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Log not found or already verified" });
    }
    res.json({ success: true, message: "Deleted successfully" });
  } catch (error) {
    res.status(500).json({ success: false, error: error.message });
  }
});

export default router;
