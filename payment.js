import express from "express";
import bcrypt from "bcrypt";
import axios from "axios";
import pool from "./db.js";
import crypto from "crypto";

const router = express.Router();

router.post("/", async (req, res) => {
  try {
    const { name, email, password, city, town, otp, metadata } = req.body;
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
      `SELECT id FROM estate_admin_users
             WHERE LOWER(name) = LOWER($1) AND LOWER(city) = LOWER($2) AND LOWER(town) = LOWER($3)`,
      [name, city, town],
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
        "https://4f8a-102-88-54-30.ngrok-free.app/api/payment/callback",
      metadata: { name, city, town },
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
      `INSERT INTO temp_payment_info (tx_ref, name, email, password, city, town) 
             VALUES ($1, $2, $3, $4, $5, $6)`,
      [reference, name, email, hashedPassword, city || null, town || null],
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
      "INSERT INTO estates (name, estate_code) VALUES ($1, $2) RETURNING id",
      [`${tempUser.name}'s Estate`, estateCode],
    );
    const estateId = estateResult.rows[0].id;

    // Subscription expiry
    const subscriptionExpiry = new Date();
    subscriptionExpiry.setFullYear(subscriptionExpiry.getFullYear() + 1);

    // Insert into estate_admin_users with city/town
    await client.query(
      `INSERT INTO estate_admin_users 
       (estate_id, name, email, password, city, town, subscription_expiry, role) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
      [
        estateId,
        tempUser.name,
        tempUser.email,
        tempUser.password,
        tempUser.city || null,
        tempUser.town || null,
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

export default router;
