import express from "express";
import bcrypt from "bcrypt";
import axios from "axios";
import pool from "./db.js";
import crypto from "crypto";
import { isAuth, ensureAdmin } from "./middlewares.js";

const router = express.Router();


const VTPASS_BASE_URL = "https://sandbox.vtpass.com/api";
const AUTH_HEADER = {
  'api-key': process.env.VTPASS_API_KEY,
  'public-key': process.env.VTPASS_PUBLIC_KEY,
};

const vtpass = {
  // Verify Meter Number or Phone Number
  verify: async (billersCode, serviceID, type = '') => {
    try {
      const response = await axios.post(`${VTPASS_BASE_URL}/merchant-verify`, {
        billersCode,
        serviceID,
        type // for electricity, use 'prepaid' or 'postpaid'
      }, { headers: AUTH_HEADER });
      return response.data;
    } catch (error) {
      return { error: error.message };
    }
  },

  // Process Payment
  pay: async (details) => {
    try {
      const response = await axios.post(`${VTPASS_BASE_URL}/pay`, {
        request_id: `GM_${Date.now()}`, // Unique ID for GateMan
        serviceID: details.serviceID,
        billersCode: details.phoneOrMeter,
        variation_code: details.variationCode, // only for Data
        amount: details.amount,
        phone: details.customerPhone,
      }, { headers: AUTH_HEADER });
      return response.data;
    } catch (error) {
      return { error: error.message };
    }
  }
};


router.get("/admin-stats", ensureAdmin, async (req, res) => {
  const { estate_id, id: admin_id } = req.user;

  try {
    const [
      securityStats,
      securityComplaints,
      securityJoinRequests,
      communityStats,
      paymentStats,
      paymentComplaints,
      eventStats,
      residentStats,
      residentComplaints,
      residentJoinRequests,
    ] = await Promise.all([
      // 1. SECURITY
      pool.query(
        `SELECT COUNT(*) as total, 
                COUNT(*) FILTER (WHERE is_on_duty = true) as on_duty 
         FROM security_users WHERE estate_id = $1`,
        [estate_id],
      ),
      pool.query(
        "SELECT COUNT(*) FROM estate_reports WHERE estate_id = $1 AND type = 'SECURITY' AND status = 'PENDING'",
        [estate_id],
      ),
      pool.query(
        "SELECT COUNT(*) FROM security_join_requests WHERE estate_id = $1",
        [estate_id],
      ),

      // 2. COMMUNITY
      pool.query(
        `SELECT COUNT(*) as total_alerts,
                COUNT(*) FILTER (WHERE admin_seen = false) as unread
         FROM posts WHERE estate_id = $1 AND category = 'Alerts'`,
        [estate_id],
      ),

      // 3. PAYMENTS
      pool.query(
        `SELECT 
            COUNT(*) FILTER (WHERE payment_date >= date_trunc('month', current_date)) as month_count,
            COUNT(*) FILTER (WHERE status = 'pending') as pending_count
         FROM payment_logs WHERE estate_id = $1`,
        [estate_id],
      ),
      pool.query(
        "SELECT COUNT(*) FROM estate_reports WHERE estate_id = $1 AND type = 'PAYMENT'",
        [estate_id],
      ),

      // 4. EVENTS
      pool.query(
        `SELECT 
            COUNT(*) as total,
            COUNT(*) FILTER (WHERE is_approved = false AND is_rejected = false) as pending,
            (SELECT json_build_object('title', title, 'date', start_date) 
             FROM estate_events 
             WHERE estate_id = $1 AND start_date >= CURRENT_DATE 
             ORDER BY start_date ASC, start_time ASC LIMIT 1) as nearest_event
         FROM estate_events WHERE estate_id = $1`,
        [estate_id],
      ),

      // 5. RESIDENTS
      pool.query("SELECT COUNT(*) FROM tenant_users WHERE estate_id = $1", [
        estate_id,
      ]),
      pool.query(
        "SELECT COUNT(*) FROM estate_reports WHERE estate_id = $1 AND type = 'GENERAL' AND status = 'PENDING'",
        [estate_id],
      ),
      pool.query("SELECT COUNT(*) FROM join_requests WHERE estate_id = $1", [
        estate_id,
      ]),
    ]);

    res.json({
      success: true,
      data: {
        security: {
          total: parseInt(securityStats.rows[0].total),
          onDuty: parseInt(securityStats.rows[0].on_duty),
          complaints: parseInt(securityComplaints.rows[0].count),
          pendingRequests: parseInt(securityJoinRequests.rows[0].count),
        },
        community: {
          totalAlerts: parseInt(communityStats.rows[0].total_alerts),
          unreadAlerts: parseInt(communityStats.rows[0].unread) || 0,
        },
        payments: {
          // FIXED: Pointed to paymentStats instead of securityStats
          monthlyCount: parseInt(paymentStats.rows[0].month_count) || 0,
          pendingPayments: parseInt(paymentStats.rows[0].pending_count),
          paymentReports: parseInt(paymentComplaints.rows[0].count),
        },
        events: {
          total: parseInt(eventStats.rows[0].total),
          pending: parseInt(eventStats.rows[0].pending),
          upcoming: eventStats.rows[0].nearest_event || {
            title: "None",
            date: null,
          },
        },
        residents: {
          total: parseInt(residentStats.rows[0].count),
          complaints: parseInt(residentComplaints.rows[0].count),
          pendingRequests: parseInt(residentJoinRequests.rows[0].count),
        },
      },
    });
  } catch (err) {
    console.error("Dashboard Stats Error:", err);
    res.status(500).json({ error: "Failed to fetch dashboard statistics" });
  }
});

// 1. Get Data/Airtime variations for the frontend
router.get("/get-variations/:serviceId", async (req, res) => {
  try {
    const response = await axios.get(
      `https://sandbox.vtpass.com/api/service-variations?serviceID=${req.params.serviceId}`,
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "public-key": process.env.VTPASS_PUBLIC_KEY,
        },
      },
    );
    res.json(response.data.content.varations); // Note: VTpass spells it "varations"
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch variations" });
  }
});

// 2. Verify Meter (Pre-payment check)
router.post("/verify-meter", async (req, res) => {
  const { billersCode, serviceID, type } = req.body;
  try {
    const response = await axios.post(
      "https://sandbox.vtpass.com/api/merchant-verify",
      { billersCode, serviceID, type }, // type is 'prepaid' or 'postpaid'
      {
        headers: {
          "api-key": process.env.VTPASS_API_KEY,
          "public-key": process.env.VTPASS_PUBLIC_KEY,
        },
      },
    );
    res.json(response.data);
  } catch (err) {
    res.status(500).json({ error: "Meter verification failed" });
  }
});

router.post("/verify-meter", async (req, res) => {
  const { billersCode, serviceID } = req.body;
  const result = await vtpass.verify(billersCode, serviceID, "prepaid");

  if (result.code === "000") {
    res.json({ success: true, name: result.content.Customer_Name });
  } else {
    res.status(400).json({ success: false, message: "Invalid Meter Number" });
  }
});

// Step 2: Process Purchase
router.post("/process-purchase", async (req, res) => {
  const { serviceID, phoneOrMeter, amount, variationCode, type } = req.body;

  const paymentDetails = {
    serviceID,
    phoneOrMeter,
    amount,
    variationCode,
    customerPhone: req.user.phone || "08011111111", // User's phone from session
  };

  const result = await vtpass.pay(paymentDetails);

  if (result.code === "000") {
    // Logic for Simon: Save this to your notifications table here!
    // INSERT INTO notifications (user_id, title, message) VALUES (...)
    res.json({ success: true, data: result });
  } else {
    res
      .status(400)
      .json({ success: false, message: result.response_description });
  }
});

export default router;
