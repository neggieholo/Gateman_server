import express from "express";
import multer from "multer";
import axios from "axios";
import { v2 as cloudinary } from "cloudinary";
import { isAuth, kycLookupLimiter } from "./middlewares.js";
import db from "../db.js"; // Your DB connection

const router = express.Router();

const storage = multer.memoryStorage();
const upload = multer({ storage, limits: { fileSize: 3 * 1024 * 1024 } });

const uploadToCloudinary = (fileBuffer, folder = "vendor_kyc") => {
  return new Promise((resolve, reject) => {
    const uploadStream = cloudinary.uploader.upload_stream(
      { folder },
      (err, res) => {
        if (err) return reject(err);
        resolve(res.secure_url);
      },
    );
    uploadStream.end(fileBuffer);
  });
};

// --- HELPER VERIFICATIONS ---
const verifyCAC = async (rcNumber) => {
  try {
    const res = await axios.get(
      `https://api.withmono.com/v3/lookup/cac?search=${rcNumber}`,
      {
        headers: { "mono-sec-key": process.env.MONO_SECRET_KEY },
      },
    );
    return res.data.data;
  } catch (e) {
    return null;
  }
};

// --- ENDPOINT 1: BUSINESS & BANKING ---
router.post(
  "/save-vendor-docs",
  isAuth,
  kycLookupLimiter,
  upload.fields([
    { name: "cacCert", maxCount: 1 },
    { name: "businessUtility", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const {
        businessName,
        cacNumber,
        tinNumber,
        accountNumber,
        bankCode,
        bankName,
        accountName,
      } = req.body;
      const vendorId = req.user.id;

      // Optional: Real-time CAC check for Business Names/Companies
      if (cacNumber) {
        const cacData = await verifyCAC(cacNumber);
        if (!cacData || cacData.status !== "ACTIVE") {
          return res
            .status(400)
            .json({
              success: false,
              message: "CAC number is inactive or invalid.",
            });
        }
      }

      const cacUrl = req.files.cacCert
        ? await uploadToCloudinary(req.files.cacCert[0].buffer)
        : null;
      const utilUrl = req.files.businessUtility
        ? await uploadToCloudinary(req.files.businessUtility[0].buffer)
        : null;

      await db.query(
        `UPDATE vendors SET 
        business_name = $1, cac_number = $2, tin_number = $3, 
        cac_url = $4, utility_url = $5, 
        bank_account_number = $6, bank_code = $7, bank_name = $8, bank_account_name = $9,
        verification_step = 2 
       WHERE id = $10`,
        [
          businessName,
          cacNumber,
          tinNumber,
          cacUrl,
          utilUrl,
          accountNumber,
          bankCode,
          bankName,
          accountName,
          vendorId,
        ],
      );

      res.json({ success: true, nextStep: 2 });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },
);

// --- ENDPOINT 2: IDENTITY (BVN/NIN) ---
router.post(
  "/save-vendor-identity",
  isAuth,
  upload.fields([
    { name: "identityDoc", maxCount: 1 },
    { name: "referenceSelfie", maxCount: 1 },
  ]),
  async (req, res) => {
    try {
      const { vendorFullName, ninNumber, bvnNumber, phoneNumber } = req.body;
      const vendorId = req.user.id;

      const [idUrl, selfieUrl] = await Promise.all([
        uploadToCloudinary(req.files.identityDoc[0].buffer),
        uploadToCloudinary(req.files.referenceSelfie[0].buffer),
      ]);

      await db.query(
        `UPDATE vendors SET 
        full_name = $1, nin_number = $2, bvn_number = $3, phone_number = $4,
        identity_url = $5, profile_picture = $6,
        verification_step = 3 
       WHERE id = $7`,
        [
          vendorFullName,
          ninNumber,
          bvnNumber,
          phoneNumber,
          idUrl,
          selfieUrl,
          vendorId,
        ],
      );

      res.json({ success: true, nextStep: 3 });
    } catch (error) {
      res.status(500).json({ success: false, message: error.message });
    }
  },
);

// --- ENDPOINT 3: FINALIZE LIVENESS ---
router.post("/finalize-kyc", isAuth, async (req, res) => {
  try {
    const { selfiePhotos } = req.body; // Array of 3 base64s
    const vendorId = req.user.id;

    const snaps = await Promise.all(
      selfiePhotos.map((b64) =>
        uploadToCloudinary(Buffer.from(b64.split(",")[1], "base64")),
      ),
    );

    await db.query(
      `UPDATE vendors SET 
        liveness_snaps = $1, 
        verification_step = 4, 
        verification_status = 'pending' 
       WHERE id = $2`,
      [snaps, vendorId],
    );

    res.json({ success: true, message: "Application submitted for review." });
  } catch (error) {
    res.status(500).json({ success: false, message: error.message });
  }
});

export default router;
