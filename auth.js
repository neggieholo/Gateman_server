import express from "express";
import passport from "passport"; 

import bcrypt from "bcrypt";
import pool from "./db.js";

const router = express.Router();


// ------------------ Register Tenant ------------------
router.post("/register/tenant", async (req, res, next) => {
  console.log("tenant registration api hit", req.body);
  const { email, password, name } = req.body;

  try {
    // 1. Check if email exists in either table
    const existingUser = await pool.query(
      `SELECT email FROM tenant_users WHERE email = $1
       UNION
       SELECT email FROM temp_tenant_users WHERE email = $1`,
      [email]
    );

    if (existingUser.rows.length > 0) {
      return res.status(400).json({ 
        error: "This email is already registered. Please login or wait for approval if your request is pending." 
      });
    }

    // 2. Proceed with registration
    const hash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO temp_tenant_users (email, password, name)
       VALUES ($1, $2, $3)
       RETURNING id, email, name, created_at`, // 🛡️ Do not return password hash
      [email, hash, name]
    );

    const user = result.rows[0];
    user.isTemp = true; // passport marker

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
    res.status(400).json({ error: "Registration failed. Please try again." });
  }
});

router.post("/login/tenant", (req, res, next) => {
  console.log("tenant login api hit", req.body);

  // Regenerate the session first to avoid old session conflicts
  req.session.regenerate((err) => {
    if (err) return next(err);

    passport.authenticate("tenant-local", (err, user, info) => {
      if (err) return next(err);
      if (!user)
        return res.status(401).json({
          error: info?.message || "Invalid credentials",
        });

      req.login(user, (err) => {
        if (err) return next(err);

        return res.json({
          success: true,
          isTemp: user.isTemp || false,
          user,
        });
      });
    })(req, res, next);
  });
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

