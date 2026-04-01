import express from "express";
import passport from "passport"; 
import firebaseAdmin from "./firebase.js";
import bcrypt from "bcrypt";
import pool from "./db.js";

import { sendRegistrationOTP } from "./emailService.js";
import crypto from "crypto";

const router = express.Router();


const OTP_SECRET = process.env.OTP_SECRET || "gate-man-local-secret";

router.post("/otp/send", async (req, res) => {
  console.log("OTP send request received for email:", req.body.email);
  const { email } = req.body;
  const otp = Math.floor(100000 + Math.random() * 900000).toString();
  const expires = Date.now() + 10 * 60000; 

  const data = `${email}.${otp}.${expires}`;
  const hash = crypto.createHmac("sha256", OTP_SECRET).update(data).digest("hex");
  const metadata = `${hash}.${expires}`;

  const emailSent = await sendRegistrationOTP(email, otp);

  if (emailSent) {
    res.json({ success: true, metadata });
  } else {
    res.status(500).json({ error: "Failed to send email" });
  }
});
// ------------------ Register Tenant ------------------
router.post("/register/tenant", async (req, res, next) => {
  const { email, password, name, otp, metadata } = req.body;

  try {
    // 1. Verify the Metadata "Proof"
    const [hash, expires] = metadata.split(".");
    
    if (Date.now() > parseInt(expires)) {
      return res.status(400).json({ error: "OTP expired. Please resend." });
    }

    const data = `${email}.${otp}.${expires}`;
    const verifyHash = crypto.createHmac("sha256", OTP_SECRET).update(data).digest("hex");

if (!crypto.timingSafeEqual(Buffer.from(verifyHash, 'hex'), Buffer.from(hash, 'hex'))) {
  return res.status(400).json({ error: "Invalid OTP code." });
}
    // 2. Security Check: Ensure email isn't already taken
    const existingUser = await pool.query(
      `SELECT email FROM tenant_users WHERE email = $1 
       UNION SELECT email FROM temp_tenant_users WHERE email = $1`,
      [email.toLowerCase().trim()]
    );

    if (existingUser.rows.length > 0) {
       return res.status(400).json({ error: "User already exists." });
    }

    // 3. Hash Password and Insert
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO temp_tenant_users (email, password, name) 
       VALUES ($1, $2, $3) RETURNING id, email, name`,
      [email, passwordHash, name]
    );

    const user = result.rows[0];
    user.isTemp = true;

    req.login(user, (err) => {
      if (err) return next(err);
      res.json({
        success: true,
        pending: true,
        message: "Tenant registered successfully. Please submit a join request to an estate.",
        user,
      });
    });

  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed." });
  }
});

router.post("/login/tenant", (req, res, next) => {
  console.log("tenant login api hit", req.body);
  passport.authenticate("tenant-local", (err, user, info) => {
    if (err || !user) return res.status(401).json({ error: info?.message });

    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);

      req.session.save(async (saveErr) => {
        if (saveErr) return next(saveErr);

        let customToken = null;

        if (!user.isTemp) {
          try {
            const postgresUserId = user.id.toString();
            customToken = await firebaseAdmin.auth().createCustomToken(postgresUserId, {
              role: "resident"
            });
          } catch (firebaseErr) {
            console.error("Firebase Token Error:", firebaseErr);
          }
        }

        return res.json({
          success: true,
          isTemp: user.isTemp || false,
          user,
          sessionId: req.sessionID,
          chatToken: customToken
        });
      });
    });
  })(req, res, next);
});


// ------------------ Admin Login ------------------
router.post("/login/admin", (req, res, next) => {
  passport.authenticate("admin-local", (err, user, info) => {
    if (err) return next(err);
    if (!user)
      return res.status(401).json({
        error: info?.message || "Invalid credentials",
      });

    req.login(user, (err) => {
      if (err) return next(err);
      const { password, ...safeUser } = user; 

      res.json({ success: true, user: safeUser });
    });
  })(req, res, next);
});


export default router;

