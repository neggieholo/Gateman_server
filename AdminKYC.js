import express from "express";
import multer from "multer";
import axios from "axios";
import { v2 as cloudinary } from "cloudinary";
import { WebApi } from "smile-identity-core";
import { isAuth, kycLookupLimiter } from "./middlewares.js";
import pool from "./db.js";

const router = express.Router();

cloudinary.config({
  cloud_name: "diubaoqcr",
  api_key: "962197146245963",
  api_secret: process.env.CLOUDINARYAPISECRET,
});

const storage = multer.memoryStorage();
const upload = multer({
  storage: storage,
  limits: { fileSize: 5 * 1024 * 1024 }, 
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype === "image/jpeg" ||
      file.mimetype === "image/png" ||
      file.mimetype === "application/pdf" 
    ) {
      cb(null, true);
    } else {
      cb(new Error("Unsupported file type"), false);
    }
  },
});

const uploadToCloudinary = (fileBuffer) => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder: "gateman_admin_kyc", resource_type: "auto" },
      (error, result) => {
        if (error) return reject(error);
        resolve(result.secure_url);
      },
    );
    uploadStream.end(fileBuffer);
  });
};

// --- 2. VERIFICATION SERVICES ---

const verifyNIN = async (nin, firstName, lastName) => {
  try {
    const response = await axios.post(
      "https://api.paystack.co/verification/identity",
      { type: "nin", number: nin, first_name: firstName, last_name: lastName },
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );
    return response.data.status;
  } catch (error) {
    return false;
  }
};

// const verifyCAC = async (rcNumber) => {
//   try {
//     const response = await axios.get(
//       `https://api.withmono.com/v3/lookup/cac?search=${rcNumber}`,
//       { headers: { "mono-sec-key": process.env.MONO_SECRET_KEY } },
//     );
//     return response.data.data;
//   } catch (error) {
//     return null;
//   }
// };

const verifyCAC = async (cacNumber) => {
  // Logic: For now, if you're skipping the API, return a dummy object 
  // so the database columns (business_type, address) get filled.
  return {
    status: "ACTIVE",
    type: cacNumber.startsWith("IT") ? "Incorporated Trustee" : "Company",
    address: "Pending Manual Verification",
    registration_date: new Date().toISOString()
  };
};

const verifyAdminNIN = async (nin) => {
  try {
    const response = await axios.post(
      "https://api.withmono.com/v2/lookup/nin",
      {
        number: nin, // The 11-digit NIN
      },
      {
        headers: { "mono-sec-key": process.env.MONO_SECRET_KEY },
      },
    );

    const nimcData = response.data.data;

    return {
      fullName: `${nimcData.first_name} ${nimcData.last_name}`,
      photo: nimcData.photo, // Base64 or URL of their official NIMC photo
      dob: nimcData.dob,
    };
  } catch (error) {
    console.error("NIN Lookup Failed:", error.response?.data || error.message);
    throw new Error("Invalid NIN or Service Down");
  }
};

// --- ENDPOINT 1: ESTATE DOCS & SETTLEMENT ACCOUNT ---
router.post(
  "/save-estate-docs",
  isAuth,
  kycLookupLimiter,
  upload.fields([
    { name: "cacCert", maxCount: 1 },
    { name: "tinCert", maxCount: 1 },
    { name: "estateUtility", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const {
        cacNumber,
        tinNumber,
        accountNumber,
        bankCode,
        accountName,
        bankName,
      } = req.body;
      const adminId = req.user.id;
      const estateId = req.user.estateId;
      const files = req.files;

      // Real-time CAC Verification
      const cacData = await verifyCAC(cacNumber);
      if (!cacData || cacData.status !== "ACTIVE") {
        return res
          .status(400)
          .json({ success: false, message: "Invalid or Inactive CAC Number." });
      }

      const cacUrl = await uploadToCloudinary(files.cacCert[0].buffer);
      const tinUrl = await uploadToCloudinary(files.tinCert[0].buffer);
      const utilUrl = files.estateUtility
        ? await uploadToCloudinary(files.estateUtility[0].buffer)
        : null;

      // Update Estate Table (Entity Details + Bank Details)
      await pool.query(
        `UPDATE estates SET 
          cac_number = $1, 
          tin_number = $2, 
          cac_cert_url = $3, 
          tin_cert_url = $4, 
          estate_utility_url = $5, 
          cac_verification_status = 'verified',
          business_type = $6,
          registered_address = $7,
          registration_date = $8,
          bank_account_number = $9,
          bank_code = $10,
          bank_account_name = $11,
          bank_name = $12
         WHERE id = $13`,
        [
          cacNumber,
          tinNumber,
          cacUrl,
          tinUrl,
          utilUrl,
          cacData.type || "Company",
          cacData.address,
          cacData.registration_date,
          accountNumber,
          bankCode,
          accountName,
          bankName,
          estateId,
        ],
      );

      // Update Admin Progress
      await pool.query(
        "UPDATE estate_admin_users SET verification_step = 2 WHERE id = $1",
        [adminId],
      );

      res.json({ success: true, nextStep: 2 });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },
);

// --- ENDPOINT 2: ADMIN IDENTITY ---
router.post(
  "/save-admin-identity",
  isAuth,
  upload.fields([
    { name: "authLetter", maxCount: 1 },
    { name: "adminUtility", maxCount: 1 },
    { name: "signature", maxCount: 1 },
    { name: "selfie", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const {
        adminFullName,
        ninNumber,
        bvnNumber,
        adminRole,
        residentialAddress,
        authorizingBodyName,
      } = req.body;

      const files = req.files;
      const adminId = req.user.id;
      const estateId = req.user.estateId;

      const [authUrl, sigUrl, selfieUrl] = await Promise.all([
        uploadToCloudinary(files.authLetter[0].buffer),
        uploadToCloudinary(files.signature[0].buffer),
        uploadToCloudinary(files.selfie[0].buffer),
      ]);

      const utilUrl = files.adminUtility
        ? await uploadToCloudinary(files.adminUtility[0].buffer)
        : null;

      // 1. Update Estate Table with authorization info
      await pool.query(
        `UPDATE estates SET 
          authorization_letter_url = $1, 
          authorizing_body_name = $2 
          WHERE id = $3`,
        [authUrl, authorizingBodyName, estateId],
      );

      // 2. Update Admin Table (Personal Identity Only)
      await pool.query(
        `UPDATE estate_admin_users SET 
          name = $1, 
          nin_number = $2, 
          bvn_number = $3,
          role = $4, 
          residential_address = $5, 
          admin_utility_url = $6, 
          signature_url = $7, 
          avatar = $8, 
          verification_step = 3,
          verification_status = 'pending' 
          WHERE id = $9`,
        [
          adminFullName,
          ninNumber,
          bvnNumber,
          adminRole,
          residentialAddress,
          utilUrl,
          sigUrl,
          selfieUrl,
          adminId,
        ],
      );

      res.json({ success: true, nextStep: 3 });
    } catch (error) {
      console.error("KYC Save Error:", error);
      res.status(500).json({ success: false, message: "Server error." });
    }
  },
);

// --- ENDPOINT 3: FINAL SELFIE & SUBMIT ---
router.post("/finalize-kyc", isAuth, async (req, res) => {
  try {
    const adminId = req.user.id;
    const { selfiePhotos } = req.body;

    const snapUploadPromises = selfiePhotos.map((base64) => {
      // Strip the data:image/jpeg;base64, prefix and convert to Buffer
      const buffer = Buffer.from(base64.split(",")[1], "base64");
      return uploadToCloudinary(buffer);
    });

    const livenessSnapsUrls = await Promise.all(snapUploadPromises);

    await pool.query(
      `UPDATE estate_admin_users SET 
       liveness_snaps = $1, 
       verification_step = 4, 
       verification_status = 'pending' 
       WHERE id = $2`,
      [livenessSnapsUrls, adminId],
    );

    res.json({ success: true, message: "Biometrics submitted successfully." });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

router.get("/status", async (req, res) => {
  try {
    const adminId = req.user.id;

    const result = await pool.query(
      "SELECT verification_status, verification_step FROM estate_admin_users WHERE id = $1",
      [adminId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Admin not found" });
    }

    const admin = result.rows[0];

    let status = "pending";
    if (admin.verification_status === "verified") status = "completed";
    if (admin.verification_status === "rejected") status = "failed";

    res.json({
      status: status,
      step: admin.verification_step,
    });
  } catch (error) {
    res.status(500).json({ error: "Internal Error" });
  }
});

router.post("/reset", isAuth, async (req, res) => {
  const { adminId, estateId } = req.body;
  const client = await pool.connect(); // Get a dedicated client from the pool

  try {
    await client.query("BEGIN"); // Start the transaction

    // 1. Reset Estates Table
    await client.query(
      `UPDATE estates SET 
        cac_number = NULL, 
        tin_number = NULL, 
        cac_cert_url = NULL, 
        estate_utility_url = NULL,
        cac_verification_status = 'pending',
        business_type = NULL,
        registered_address = NULL,
        registration_date = NULL,
        authorization_letter_url = NULL,
        authorizing_body_name = NULL,
        status = 'unverified'
       WHERE id = $1`,
      [estateId],
    );

    // 2. Reset Admin Table
    await client.query(
      `UPDATE estate_admin_users SET 
        name = NULL, nin_number = NULL, bvn_number = NULL, role = NULL, address = NULL, 
        admin_utility_url = NULL, avatar = NULL, signature_url = NULL,
        verification_step = 0, verification_status = 'pending' 
       WHERE id = $1`,
      [adminId],
    );

    await client.query("COMMIT"); // Save changes
    res.json({ success: true, message: "Reset successful" });
  } catch (error) {
    await client.query("ROLLBACK"); // Undo everything if it fails
    console.error("Reset Error:", error);
    res.status(500).json({ success: false, message: error.message });
  } finally {
    client.release(); // IMPORTANT: Release the client back to the pool
  }
});

// Add this to your backend routes
router.get("/resolve-bank", async (req, res) => {
  const { accountNumber, bankCode } = req.query;

  try {
    const response = await axios.get(
      `https://api.paystack.co/bank/resolve?account_number=${accountNumber}&bank_code=${bankCode}`,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
        },
      },
    );

    res.json(response.data);
  } catch (error) {
    console.error(
      "Bank Resolution Error:",
      error.response?.data || error.message,
    );
    res
      .status(400)
      .json({ status: false, message: "Could not resolve account" });
  }
});

// --- ADMIN DASHBOARD ENDPOINT: APPROVE KYC ---
router.post("/admin/approve-kyc", isAuth, async (req, res) => {
  const { estateId, adminId } = req.body;

  try {
    // 1. Fetch all saved info for this estate and admin
    const estateResult = await pool.query("SELECT * FROM estates WHERE id = $1", [
      estateId,
    ]);
    const adminResult = await pool.query(
      "SELECT * FROM estate_admin_users WHERE id = $1",
      [adminId],
    );

    const estate = estateResult.rows[0];
    const admin = adminResult.rows[0];

    // 2. Create Paystack Subaccount
    const paystackResponse = await axios.post(
      "https://api.paystack.co/subaccount",
      {
        business_name: estate.estate_name,
        settlement_bank: admin.bank_code, // Assuming collected at signup
        account_number: admin.account_number,
        percentage_charge: 5.0,
        metadata: JSON.stringify({
          admin_id: adminId,
          estate_id: estateId,
          cac_number: estate.cac_number,
          tin_number: estate.tin_number,
          selfie_url: admin.selfie_url,
        }),
      },
      {
        headers: { Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}` },
      },
    );

    const subaccountCode = paystackResponse.data.data.subaccount_code;

    // 3. Update status to 'verified' and save subaccount code
    await pool.query(
      "UPDATE estates SET status = 'verified', paystack_subaccount_code = $1 WHERE id = $2",
      [subaccountCode, estateId],
    );

    await pool.query(
      "UPDATE estate_admin_users SET status = 'active' WHERE id = $1",
      [adminId],
    );

    res.json({
      success: true,
      message: "Estate approved and subaccount created.",
    });
  } catch (error) {
    res.status(500).json({
      success: false,
      message: error.response?.data?.message || error.message,
    });
  }
});

router.post("/smile-id/token", isAuth, async (req, res) => {
  try {
    const { adminId, ninNumber } = req.body;

    // Initialize connection
    const connection = new WebApi(
      process.env.SMILE_PARTNER_ID,
      process.env.SMILE_CALLBACK_URL,
      process.env.SMILE_API_KEY,
      process.env.SMILE_SERVER,
    );

    const request_params = {
      user_id: `admin_${adminId}`,
      job_id: `job_${Date.now()}`,
      product: "biometric_kyc",
      id_number: ninNumber,
      id_type: "NIN",
      callback_url: process.env.SMILE_CALLBACK_URL,
    };

    const result = await connection.get_web_token(request_params);

    // Return the token to the frontend
    res.json(result);
  } catch (error) {
    console.error("Smile ID Token Error:", error);
    res.status(500).json({ success: false, message: error.message });
  }
});

// routes/kyc.js
router.post("/callback", async (req, res) => {
  const result = req.body;

  try {
    // 1. Extract adminId (cleaning prefix if you used one)
    const adminId = result.PartnerParams.user_id.replace("admin_", "");

    // Result Codes: 0810 (Accepted), 0812 (Accepted with warning)
    const isSuccess =
      result.ResultCode === "0810" || result.ResultCode === "0812";
    const confidence = result.ConfidenceValue || 0;

    if (isSuccess) {
      // 2. Map Smile ID fields to your estate_admin_users columns
      await pool.query(
        `UPDATE estate_admin_users 
         SET 
            is_verified = true,
            verification_status = 'verified',
            verification_step = 4,
            smile_id_status = $1,
            smile_id_job_id = $2,
            smile_id_confidence = $3,
            is_liveness_verified = $4,
            verified_at = CURRENT_TIMESTAMP
         WHERE id = $5`,
        [
          result.ResultText, // smile_id_status
          result.SmileJobID, // smile_id_job_id
          confidence, // smile_id_confidence
          true, // is_liveness_verified
          adminId, // id
        ],
      );
      console.log(`KYC Verified for Admin: ${adminId}`);
    } else {
      // 3. Handle Failure or Manual Review
      await pool.query(
        `UPDATE estate_admin_users 
         SET 
            verification_status = 'rejected',
            smile_id_status = $1,
            kyc_notes = $2
         WHERE id = $3`,
        [result.ResultText, `Failed: ${result.ResultText}`, adminId],
      );
      console.log(`KYC Rejected for Admin: ${adminId} - ${result.ResultText}`);
    }

    // Always signal success to Smile ID
    res.status(200).send("Callback received");
  } catch (error) {
    console.error("Smile ID Callback Error:", error);
    // Return 500 so Smile ID retries if it's a transient DB error
    res.status(500).send("Internal Server Error");
  }
});

export default router;
