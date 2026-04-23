import axios from "axios";
import crypto from "crypto";
import express from "express";
import bcrypt from "bcrypt";
import pool from "./db.js";
import { isAuth } from "./middlewares.js";

const router = express.Router();

router.post("/join-request", isAuth, async (req, res) => {
  const { estateId } = req.body;
  const vendorId = req.user.id; // This will be the UUID from your JWT/Session

  try {
    // Check if vendor has finished KYC and is verified
    const vendorCheck = await db.query(
      "SELECT identity_verified FROM vendors WHERE id = $1",
      [vendorId],
    );

    if (!vendorCheck.rows[0]?.identity_verified) {
      return res.status(403).json({
        success: false,
        message:
          "Please complete your identity verification before joining an estate.",
      });
    }

    await db.query(
      "INSERT INTO vendor_estate_requests (vendor_id, estate_id) VALUES ($1, $2)",
      [vendorId, estateId],
    );

    res.json({ success: true, message: "Request sent successfully!" });
  } catch (err) {
    if (err.code === "23505") {
      return res
        .status(400)
        .json({
          success: false,
          message: "You have already applied to this estate.",
        });
    }
    res.status(500).json({ success: false, message: err.message });
  }
});

export default router;