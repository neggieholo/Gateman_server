import axios from "axios";
import crypto from "crypto";
import express from "express";
import passport from "passport";
import firebaseAdmin from "./firebase.js";
import bcrypt from "bcrypt";
import pool from "./db.js";

const router = express.Router();

const sendSmsOtp = async (phoneNumber, otp) => {
  const data = {
    api_key: process.env.TERMII_API_KEY,
    to: phoneNumber,
    from: "GATEMAN", // Your approved Sender ID
    sms: `Your GateMan verification code is ${otp}. Valid for 10 minutes.`,
    type: "plain",
    channel: "dnd", // Use 'dnd' channel to ensure delivery to DND-active numbers
  };

  try {
    const response = await axios.post(
      "https://api.ng.termii.com/api/sms/send",
      data,
    );
    return response.data;
  } catch (error) {
    console.error("Termii Error:", error.response?.data || error.message);
    return null;
  }
};

router.post("/vendor/verify-bvn", async (req, res) => {
  const { bvn, phoneNumber } = req.body;
  const PAYSTACK_SECRET = process.env.PAYSTACK_SECRET_KEY;

  try {
    const response = await axios.get(
      `https://api.paystack.co/bank/resolve_bvn/${bvn}`,
      {
        headers: { Authorization: `Bearer ${PAYSTACK_SECRET}` },
      },
    );

    if (response.data.status) {
      const bankData = response.data.data;
    
      const normalizedInput = phoneNumber.replace(/\D/g, "").slice(-10);
      const normalizedBank = bankData.mobile.replace(/\D/g, "").slice(-10);

      if (normalizedInput !== normalizedBank) {
        return res.status(400).json({
          error:
            "The phone number provided does not match the one linked to this BVN.",
        });
      }

      req.session.pendingBvnData = {
        first_name: bankData.first_name,
        last_name: bankData.last_name,
        bvn: bvn,
        phone: bankData.mobile,
      };

      res.json({
        success: true,
        message:
          "BVN matched. An OTP has been sent to your registered bank phone number.",
      });
    }
  } catch (error) {
    const msg = error.response?.data?.message || "BVN verification failed";
    res.status(400).json({ error: msg });
  }
});
