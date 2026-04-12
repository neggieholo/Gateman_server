// routes/master.js
import express from "express";
import pool from "./db.js";
import { isSuperAdmin, hasPermission } from "./middlewares.js";

const router = express.Router();

// Fetch all pending estate verification requests
router.get(
  "/requests",
  isSuperAdmin,
  hasPermission("manage_estates"),
  async (req, res) => {
    try {
      const query = `
      SELECT 
        -- Estate Entity Data
        e.id AS estate_id,
        e.name AS estate_name,
        e.cac_number,
        e.tin_number,
        e.cac_cert_url,
        e.tin_cert_url,
        e.authorization_letter_url,
        e.authorizing_body_name,
        e.estate_utility_url,
        e.cac_verification_status,
        e.bank_account_name,
        e.bank_account_number,
        e.city,
        e.town,
        e.business_type, 

        -- Admin User Data
        u.id AS admin_id,
        u.name AS admin_name,
        u.email AS admin_email,
        u.residential_address,
        u.verification_status AS admin_status,
        u.verification_step,
        u.nin_number,
        u.bvn_number,
        u.admin_selfie_url,
        u.liveness_snaps,
        u.signature_url,
        u.identity_type,
        u.admin_utility_url,
        u.avatar,

        -- Metadata
        u.kyc_submitted_at
      FROM estates e
      JOIN estate_admin_users u ON e.id = u.estate_id
      WHERE u.verification_status = 'pending' 
         OR e.cac_verification_status = 'pending'
      ORDER BY u.kyc_submitted_at DESC;
    `;

      const result = await pool.query(query);
      res.json({ success: true, requests: result.rows });
    } catch (err) {
      console.error("Fetch Requests Error:", err);
      res.status(500).json({ error: "Failed to fetch verification requests." });
    }
  },
);

// router.post("/verify-external", isSuperAdmin, async (req, res) => {
//   const { type, value } = req.body; // type: 'CAC' or 'TIN'

//   try {
//     // Paystack uses different endpoints for different verification types
//     // Note: Verification usually incurs a small fee on your Paystack balance
//     const endpoint =
//       type === "CAC"
//         ? `https://api.paystack.co/verification/cac?registration_number=${value}`
//         : `https://api.paystack.co/verification/tin?tin=${value}`;

//     const response = await axios.get(endpoint, {
//       headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
//     });

//     res.json({ success: true, data: response.data.data });
//   } catch (err) {
//     console.error(`Paystack ${type} Error:`, err.response?.data || err.message);
//     res.status(400).json({
//       success: false,
//       error: `External ${type} verification failed.`,
//     });
//   }
// });


// router.post("/verify-external", isSuperAdmin, async (req, res) => {
router.post("/verify-external", async (req, res) => {
  console.log("Verification api hit!")
  const { type, value } = req.body;

  try {
    // Artificial delay to simulate network latency
    await new Promise((resolve) => setTimeout(resolve, 1000));

    // Simple logic: if value is '12345', simulate a "Not Found" error
    if (value === "12345") {
      return res.status(404).json({
        success: false,
        error: `${type} number ${value} was not found in the registry.`,
      });
    }

    // Success Mock Data
    const mockData = {
      CAC: {
        company_name: "GATEMAN ESTATE TECHNOLOGIES LTD",
        registration_date: "2024-05-15",
        status: "Active",
        address: "12 Admiralty Way, Lekki Phase 1, Lagos, Nigeria",
        rc_number: value,
      },
      TIN: {
        name: "GATEMAN ESTATE TECHNOLOGIES LTD",
        registration_date: "2024-06-01",
        status: "Validated",
        address: "12 Admiralty Way, Lekki Phase 1, Lagos, Nigeria",
        tin: value,
      },
    };

    const result = mockData[type] || mockData.CAC;

    res.json({
      success: true,
      data: result,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: "Internal Server Error during verification.",
    });
  }
});

router.post(
  "/process-estate",
  isSuperAdmin,
  hasPermission("manage_estates"),
  async (req, res) => {
    const { estate_id, admin_id, action, reason } = req.body;
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      if (action === "approve") {
        await client.query(
          `UPDATE estates SET cac_verification_status = 'verified' WHERE id = $1`,
          [estate_id],
        );
      } else {
        await client.query(
          `UPDATE estates SET cac_verification_status = 'rejected' WHERE id = $1`,
          [estate_id],
        );

        await client.query(
          `UPDATE estate_admin_users SET 
          verification_status = 'rejected', 
          verification_step = 1 
         WHERE id = $1`,
          [admin_id],
        );

        await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
         VALUES ($1, $2, $3, $4)`,
          [estate_id, admin_id, "admin", "KYC Rejected", reason, "kyc_update"],
        );
      }

      await client.query("COMMIT");
      res.json({ success: true, message: `Estate successfully ${action}ed.` });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Process Estate Error:", err);
      res.status(500).json({ error: "Transaction failed." });
    } finally {
      client.release();
    }
  },
);

// router.post("/verify-admin-id", isSuperAdmin, async (req, res) => {
//   const { type, value, estate_id } = req.body;

//   try {
//     // 1. Check if the Estate itself is verified first
//     const estate = await db.query(
//       "SELECT cac_verification_status FROM estates WHERE id = ?",
//       [estate_id],
//     );

//     if (!estate || estate.cac_verification_status !== "verified") {
//       return res.status(400).json({
//         success: false,
//         error: "Cannot verify Admin: Estate CAC must be verified first.",
//       });
//     }

//     // 2. Simulate/Call External Identity API (SmileID/Dojah/etc)
//     // For now, returning mock data for showcasing
//     const mockIdentity = {
//       full_name: "Simon Dev",
//       dob: "1995-10-12",
//       address: "123 Tech Hub Close, Lagos",
//       status: "Verified",
//     };

//     // 3. Update Admin Status in DB since the check passed
//     await db.query(
//       "UPDATE estate_admins SET admin_status = 'verified' WHERE estate_id = ?",
//       [estate_id],
//     );

//     res.json({
//       success: true,
//       data: mockIdentity,
//     });
//   } catch (err) {
//     console.error("Admin Verification Error:", err);
//     res
//       .status(500)
//       .json({ success: false, error: "Server error during verification." });
//   }
// });

// router.post("/verify-admin-id", isSuperAdmin, async (req, res) => {
router.post("/verify-admin-id", async (req, res) => {
  const { type, value, estate_id } = req.body;

  try {
    // 1. Simulate network latency
    await new Promise((resolve) => setTimeout(resolve, 1500));

    // 2. Simulate the "Estate Check"
    // In a real scenario, you'd query your DB here.
    // For the mock, let's assume any estate_id starting with 'err' is unverified.
    if (estate_id && estate_id.toString().startsWith('err')) {
      return res.status(400).json({
        success: false,
        error: "Cannot verify Admin: Estate CAC must be verified first."
      });
    }

    // 3. Logic for "Not Found" simulation
    if (value === "000000000") {
      return res.status(404).json({
        success: false,
        error: `${type} number not found in national database.`
      });
    }

    // 4. Success Mock Data (Shape matches your frontend result.data)
    const mockIdentity = {
      full_name: "Simon Effiong", 
      dob: "1994-03-24",
      gender: "Male",
      address: "No 15, Tech Innovation Hub, Yaba, Lagos",
      photo_url: "https://i.pravatar.cc/150?u=simon", // Fake avatar
      status: "Verified",
    };

    res.json({
      success: true,
      data: mockIdentity
    });

  } catch (err) {
    res.status(500).json({
      success: false,
      error: "Internal identity server timeout."
    });
  }
});

router.post("/process-admin", isSuperAdmin, async (req, res) => {
  const { estate_id, admin_id, action, reason } = req.body;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1. Mandatory Check: Estate must be verified for Admin Approval to happen
    if (action === "approve") {
      const estateRes = await client.query(
        "SELECT cac_verification_status FROM estates WHERE id = $1",
        [estate_id],
      );

      if (
        !estateRes.rows[0] ||
        estateRes.rows[0].cac_verification_status !== "verified"
      ) {
        throw new Error(
          "Cannot approve Admin. The Estate CAC must be verified first.",
        );
      }

      // Update Admin to Verified and move to Step 2 (e.g., wallet/subscription setup)
      await client.query(
        `UPDATE estate_admin_users SET 
           verification_status = 'verified', 
           verification_step = 2 
           WHERE id = $1`,
        [admin_id],
      );
    } else {
      // REJECT LOGIC
      // Update Admin to Rejected and reset to Step 1 for re-submission
      await client.query(
        `UPDATE estate_admin_users SET 
           verification_status = 'rejected', 
           verification_step = 1 
           WHERE id = $1`,
        [admin_id],
      );

      // Notify Admin of rejection
      await client.query(
        `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, $3, $4, $5, $6)`,
        [
          estate_id,
          admin_id,
          "admin",
          "Admin Identity Rejected",
          reason,
          "kyc_update",
        ],
      );
    }

    await client.query("COMMIT");
    res.json({ success: true, message: `Admin successfully ${action}ed.` });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Process Admin Error:", err);
    res
      .status(400)
      .json({ success: false, error: err.message || "Transaction failed." });
  } finally {
    client.release();
  }
});

router.get(
  "/all-active",
  isSuperAdmin,
  hasPermission("manage_estates"),
  async (req, res) => {
    try {
      const query = `
      SELECT 
        -- Core Identity
        e.id AS estate_id,
        e.name AS estate_name,
        e.estate_code,
        e.city,
        e.town,
        e.created_at,
        
        -- Business & Verification Data
        e.cac_number,
        e.tin_number,
        e.business_type,
        e.registered_address,
        e.registration_date,
        e.cac_verification_status,
        
        -- Document URLs
        e.cac_cert_url,
        e.tin_cert_url,
        e.estate_utility_url,
        e.authorization_letter_url,
        e.authorizing_body_name,

        -- Financial & Paystack Data
        e.bank_account_number,
        e.bank_account_name,
        e.bank_name,
        e.bank_code,
        e.paystack_subaccount_code,
        e.wallet_balance,

        -- Aggregates
        (SELECT COUNT(*) FROM residents WHERE estate_id = e.id) AS tenant_count,

        -- Primary Admin Data
        u.id AS admin_id,
        u.name AS admin_name,
        u.email AS admin_email,
        u.verification_status AS admin_status
      FROM estates e
      JOIN estate_admin_users u ON e.id = u.estate_id
      WHERE e.cac_verification_status = 'verified' 
        AND u.verification_status = 'verified'
      ORDER BY e.name ASC;
    `;

      const result = await pool.query(query);
      res.json({ success: true, estates: result.rows });
    } catch (err) {
      console.error("Fetch Estates Error:", err);
      res.status(500).json({ error: "Failed to fetch active estates." });
    }
  },
);

export default router;
