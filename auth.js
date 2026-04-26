import express from "express";
import passport from "passport"; 
import firebaseAdmin from "./firebase.js";
import bcrypt from "bcrypt";
import pool from "./db.js";
import { isSuperAdmin } from "./middlewares.js";

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
      [email.trim()]
    );

    if (existingUser.rows.length > 0) {
       return res.status(400).json({ error: "Email already registered." });
    }

    // 3. Hash Password and Insert
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO temp_tenant_users (email, password, name, role) 
       VALUES ($1, $2, $3, 'TENANT') RETURNING id, email, name`,
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
    console.log("Registration error:", err)
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


// ------------------ Register Security ------------------
router.post("/register/security", async (req, res, next) => {
  const { email, password, name, phone, otp, metadata } = req.body;
  // console.log("Security registration attempt for email:", email, "and phone:", phone);

  try {
    // 1. Verify OTP
    const [hash, expires] = metadata.split(".");
    if (Date.now() > parseInt(expires)) return res.status(400).json({ error: "OTP expired." });

    const data = `${email}.${otp}.${expires}`;
    const verifyHash = crypto.createHmac("sha256", OTP_SECRET).update(data).digest("hex");

    if (!crypto.timingSafeEqual(Buffer.from(verifyHash, 'hex'), Buffer.from(hash, 'hex'))) {
      return res.status(400).json({ error: "Invalid OTP code." });
    }

    const existing = await pool.query(
      `SELECT email FROM security_users WHERE email = $1 OR phone = $2 
       UNION 
       SELECT email FROM temp_security_users WHERE email = $1 OR phone = $2`,
      [email.toLowerCase().trim(), phone.trim()]
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: "Email or Phone number already registered." });
    }

    // 3. Insert into TEMP including phone
    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO temp_security_users (email, password, name, phone, role) 
       VALUES ($1, $2, $3, $4, 'SECURITY') RETURNING id, email, name, phone, role`,
      [email.trim(), passwordHash, name, phone.trim()]
    );

    const user = result.rows[0];
    user.isTemp = true;

    req.login(user, (err) => {
      if (err) return next(err);
      res.json({ success: true, pending: true, user });
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Registration failed." });
  }
});

// ------------------ Login Security ------------------
router.post("/login/security", (req, res, next) => {
  console.log("Security login attempt:", req.body.email, req.body.password);
  
  passport.authenticate("security-local", (err, user, info) => {
    if (err || !user) {
      console.log("Authentication failed for security:", info);
      return res.status(401).json({ error: info?.message || "Login failed" });
    }

    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);

      // Save session to store before responding
      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        return res.json({
          success: true,
          isTemp: user.isTemp || false,
          user, // Contains id, name, email, role, and estate_name (if not temp)
          sessionId: req.sessionID
        });
      });
    });
  })(req, res, next);
});

// ------------------ Super Admin Registration ------------------
// Note: In production, wrap this in isAuth and a permission check
router.post("/register/super-admin", isSuperAdmin, async (req, res) => {
  const { fullName, email, password, permissions } = req.body;

  // Basic validation to prevent empty strings in the DB
  if (!fullName || !email || !password) {
    return res
      .status(400)
      .json({ error: "All fields (Name, Email, Password) are required." });
  }

  try {
    // 1. Check for existing admin (Case-insensitive)
    const normalizedEmail = email.toLowerCase().trim();
    const existing = await pool.query(
      "SELECT id FROM super_admins WHERE email = $1",
      [normalizedEmail],
    );

    if (existing.rows.length > 0) {
      return res.status(400).json({ error: "Admin email already exists." });
    }

    // 2. Securely hash the password
    const hashedPassword = await bcrypt.hash(password, 10);

    // 3. Set Default permissions
    // If 'all_access' is passed as true, we can ignore the rest.
    const adminPermissions = permissions || {
      all_access: false,
      manage_estates: true,
      manage_finances: false,
      view_audit_logs: true,
    };

    // 4. Insert and return the safe user object
    const result = await pool.query(
      `INSERT INTO super_admins (full_name, email, password_hash, permissions, role) 
       VALUES ($1, $2, $3, $4, $5) 
       RETURNING id, full_name, email, permissions, role`,
      [
        fullName.trim(),
        normalizedEmail,
        hashedPassword,
        JSON.stringify(adminPermissions),
        "SUPER_ADMIN",
      ],
    );

    // 5. Success response (excluding the hash for security)
    res.status(201).json({
      success: true,
      message: "Super Admin created successfully",
      admin: result.rows[0],
    });
  } catch (err) {
    console.error("Super Admin Reg Error:", err);
    res
      .status(500)
      .json({ error: "Internal server error during registration." });
  }
});

// ------------------ Super Admin Login ------------------
router.post("/login/super-admin", (req, res, next) => {
  console.log("Super admin auth api hit!")
  passport.authenticate("super-admin-local", (err, user, info) => {
    if (err) return next(err);
    if (!user) return res.status(401).json({ error: info?.message || "Unauthorized" });

    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);
        
        // Remove sensitive hash before sending to frontend
        const { password_hash, ...safeUser } = user;
        safeUser.role = "SUPER_ADMIN"; 

        res.json({
          success: true,
          user: safeUser,
          sessionId: req.sessionID
        });
      });
    });
  })(req, res, next);
});

// ------------------ Register Vendor ------------------
router.post("/register/vendor", async (req, res, next) => {
  const { email, password, full_name, business_name, service_category, otp, metadata } = req.body;

  try {
    const [hash, expires] = metadata.split(".");
    
    if (Date.now() > parseInt(expires)) {
      return res.status(400).json({ error: "OTP expired. Please resend." });
    }

    const data = `${email}.${otp}.${expires}`;
    const verifyHash = crypto.createHmac("sha256", OTP_SECRET).update(data).digest("hex");

    if (!crypto.timingSafeEqual(Buffer.from(verifyHash, 'hex'), Buffer.from(hash, 'hex'))) {
      return res.status(400).json({ error: "Invalid OTP code." });
    }

    // 2. Security Check: Ensure email isn't already taken in vendors table
    const normalizedEmail = email.toLowerCase().trim();
    const existingVendor = await pool.query(
      "SELECT email FROM vendors WHERE email = $1",
      [normalizedEmail]
    );

    if (existingVendor.rows.length > 0) {
       return res.status(400).json({ error: "This email is already registered as a vendor." });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const result = await pool.query(
      `INSERT INTO vendors (email, password_hash, full_name, business_name, service_category, role, identity_verified) 
       VALUES ($1, $2, $3, $4, $5, 'VENDOR', false) 
       RETURNING id, email, full_name, role`,
      [
        normalizedEmail,
        passwordHash,
        full_name,
        business_name || null,
        service_category,
      ],
    );

    const user = result.rows[0];

    req.login(user, (err) => {
      if (err) return next(err);
      res.json({
        success: true,
        message: "Vendor registered successfully.",
        user,
      });
    });

  } catch (err) {
    console.error("Vendor Registration Error:", err);
    res.status(500).json({ error: "Registration failed." });
  }
});

// ------------------ Login Vendor ------------------
router.post("/login/vendor", (req, res, next) => {
  console.log("Vendor login attempt:", req.body.email);
  
  passport.authenticate("vendor-local", (err, user, info) => {
    if (err || !user) {
      return res.status(401).json({ error: info?.message || "Login failed" });
    }

    req.login(user, (loginErr) => {
      if (loginErr) return next(loginErr);

      req.session.save((saveErr) => {
        if (saveErr) return next(saveErr);

        return res.json({
          success: true,
          user, // Contains id, full_name, email, role, etc.
          sessionId: req.sessionID
        });
      });
    });
  })(req, res, next);
});

export default router;

