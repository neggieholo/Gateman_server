import express from "express";
import bcrypt from "bcrypt";
import axios from "axios";
import pool from "./db.js";
import crypto from "crypto";
import { io } from "./server.js";
import {
  isAuth,
  ensureAdmin,
  authorizeEstate,
  verifyPermission,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import { sendRegistrationOTP } from "./emailService.js";
import { createAppAuditLog, provisionEstateAccount } from "./helpers.js";

const router = express.Router();

const OTP_SECRET = process.env.OTP_SECRET;

const DEFAULT_TIERS = {
  monthly: 0,
  six_months: 0,
  twelve_months: 0,
  twenty_four_months: 0,
};

const getTierKey = (months) => {
  const num = Number(months);
  if (num === 24) return "twenty_four_months";
  if (num === 12) return "twelve_months";
  if (num === 6) return "six_months";
  return "monthly";
};

// Fallback pricing matrix using multi-tier structure
const DEFAULT_PRICING_MATRIX = {
  base_platform_price: {
    monthly: 4000,
    six_months: 0,
    twelve_months: 0,
    twenty_four_months: 0,
  },
  modules: {
    payments: {
      monthly: 1500,
      six_months: 0,
      twelve_months: 0,
      twenty_four_months: 0,
    },
    security: {
      monthly: 2000,
      six_months: 0,
      twelve_months: 0,
      twenty_four_months: 0,
    },
    community: {
      monthly: 1200,
      six_months: 0,
      twelve_months: 0,
      twenty_four_months: 0,
    },
    facility_bookings: {
      monthly: 1000,
      six_months: 0,
      twelve_months: 0,
      twenty_four_months: 0,
    },
    services_dispatch: {
      monthly: 1000,
      six_months: 0,
      twelve_months: 0,
      twenty_four_months: 0,
    },
  },
};

// Helper: extracts price by key & duration with fallback
const getPriceForTier = (priceObj, tierKey) => {
  if (typeof priceObj === "number") return priceObj; // backwards compatibility if flat number
  if (priceObj && typeof priceObj === "object") {
    return Number(priceObj[tierKey]) || 0;
  }
  return 0;
};

router.post("/otp/send", async (req, res) => {
  try {
    const { email } = req.body;

    if (!email) {
      return res
        .status(400)
        .json({ success: false, message: "Email is required" });
    }

    const trimmedEmail = email.trim().toLowerCase();

    // 1. Check if user already exists
    const existingAdminResult = await pool.query(
      `SELECT email, password, name, permissions FROM estate_admin_users WHERE LOWER(email) = $1 LIMIT 1`,
      [trimmedEmail],
    );

    if (existingAdminResult.rows.length > 0) {
      return res.status(400).json({
        success: false,
        message: "This email has already been registered to another account",
      });
    }

    // 2. Generate OTP and Hash
    const otp = Math.floor(100000 + Math.random() * 900000).toString();
    const expires = Date.now() + 10 * 60000;

    const data = `${trimmedEmail}.${otp}.${expires}`;
    const hash = crypto
      .createHmac("sha256", OTP_SECRET)
      .update(data)
      .digest("hex");
    const metadata = `${hash}.${expires}`;

    // 3. Send Email
    const emailSent = await sendRegistrationOTP(trimmedEmail, otp);

    if (emailSent) {
      return res.json({ success: true, metadata });
    } else {
      return res
        .status(500)
        .json({ success: false, message: "Failed to send email" });
    }
  } catch (error) {
    console.error("Error sending registration OTP:", error);
    return res
      .status(500)
      .json({ success: false, message: "Internal server error" });
  }
});

router.post("/", async (req, res) => {
  try {
    const {
      name,
      email: bodyEmail,
      password,
      state,
      lga,
      address,
      otp,
      metadata,
      adminName,
      selectedPlan,
      planDuration = 1,
    } = req.body;

    // console.log("Reg body:", req.body);
    const configuredPlan = selectedPlan;
    const userEmail = (req.user?.email || bodyEmail)?.trim().toLowerCase();
    const selectedAddOns = configuredPlan?.selectedAddOns || [];
    const isTrial = Boolean(configuredPlan?.isTrial);
    const months = Math.max(1, Number(planDuration) || 1);
    const tierKey = getTierKey(months);

    if (!name || !userEmail || !configuredPlan) {
      return res.status(400).json({
        error: "Estate name, email, and selected plan are required",
      });
    }

    // Existing Admin Validation
    const existingAdminResult = await pool.query(
      `SELECT email, password, name, permissions FROM estate_admin_users WHERE LOWER(email) = $1 LIMIT 1`,
      [userEmail],
    );

    const isExistingAdmin = existingAdminResult.rows.length > 0;
    let finalHashedPassword = null;
    let finalAdminName = adminName;

    if (isExistingAdmin) {
      const adminRecord = existingAdminResult.rows[0];
      const permissions = adminRecord.permissions || [];
      if (!permissions.includes("all-access")) {
        return res.status(403).json({
          error:
            "You do not have sufficient permissions to register a new estate.",
        });
      }
      finalAdminName = adminRecord.name || adminName || "Root Admin";
    } else {
      if (!password) {
        return res
          .status(400)
          .json({ error: "Password is required for new accounts." });
      }

      if (!metadata || !otp) {
        return res
          .status(400)
          .json({ error: "OTP verification details are required." });
      }

      const [hash, expires] = metadata.split(".");

      if (Date.now() > parseInt(expires)) {
        return res.status(400).json({ error: "OTP expired. Please resend." });
      }

      const data = `${userEmail}.${otp}.${expires}`;
      const verifyHash = crypto
        .createHmac("sha256", OTP_SECRET)
        .update(data)
        .digest("hex");

      if (verifyHash !== hash) {
        return res.status(400).json({ error: "Invalid OTP code." });
      }

      finalHashedPassword = await bcrypt.hash(password, 10);
    }

    // Duplicate Estate Check
    const estateCheck = await pool.query(
      `SELECT id FROM estates WHERE LOWER(name) = LOWER($1) AND LOWER(state) = LOWER($2) AND LOWER(lga) = LOWER($3)`,
      [name, state, lga],
    );

    if (estateCheck.rows.length > 0) {
      return res.status(400).json({
        error: "An estate with this name already exists in this location.",
      });
    }

    const reference = `TRIAL_${userEmail.replace("@", "-")}_${Date.now()}`;
    const planPayload = { selected_add_ons: selectedAddOns, is_trial: isTrial };

    // ─── IF TRIAL: DIRECT PROVISIONING ───
    if (isTrial) {
      const client = await pool.connect();
      try {
        await client.query("BEGIN");

        const trialExpiry = new Date();
        trialExpiry.setDate(trialExpiry.getDate() + 30);

        const tempUserData = {
          name,
          state,
          lga,
          street_address: address,
          root_admin: finalAdminName,
          email: userEmail,
          plan: planPayload,
          is_existing: isExistingAdmin,
          password: finalHashedPassword,
        };

        const estateId = await provisionEstateAccount(client, {
          tempUser: tempUserData,
          paidAmount: 0,
          paymentChannel: "FREE_TRIAL",
          reference,
          durationMonths: 1,
          expiryDate: trialExpiry,
          gatewayMetadata: { mode: "TRIAL_ACTIVATION" },
        });

        await client.query("COMMIT");

        const successUrl = `https://gatemanhq.com/trial-success`;

        return res.json({
          isTrial: true,
          message: "Trial account created successfully.",
          estateId,
          paymentLink: successUrl,
        });
      } catch (err) {
        await client.query("ROLLBACK");
        throw err;
      } finally {
        client.release();
      }
    }

    // ─── IF PAID: PAYSTACK FLOW ───
    const pricingResult = await pool.query(
      `SELECT value FROM system_settings WHERE setting_key = 'subscription_pricing'`,
    );

    const pricingMatrix =
      pricingResult.rows.length > 0
        ? typeof pricingResult.rows[0].value === "string"
          ? JSON.parse(pricingResult.rows[0].value)
          : pricingResult.rows[0].value
        : DEFAULT_PRICING_MATRIX;

    const baseFee = getPriceForTier(pricingMatrix.base_platform_price, tierKey);
    const modulesFee = selectedAddOns.reduce(
      (sum, key) =>
        sum + getPriceForTier(pricingMatrix.modules?.[key], tierKey),
      0,
    );
    const totalMonthlyNaira = baseFee + modulesFee;

    // Total calculation: Monthly sum * duration * 100 kobo
    const amountInKobo = Math.round(totalMonthlyNaira * months * 100);

    const paystackRef = `${userEmail.replace("@", "-")}_${Date.now()}`;

    const paymentData = {
      email: userEmail,
      amount: amountInKobo,
      reference: paystackRef,
      callback_url: "https://gatemanhq.com/api/payment/callback",
      metadata: {
        name,
        state,
        lga,
        selectedAddOns,
        isTrial,
        planDuration: months,
      },
    };

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      paymentData,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_TEST_KEY}`,
          "Content-Type": "application/json",
        },
      },
    );

    await pool.query(
      `INSERT INTO temp_payment_info (tx_ref, name, email, password, state, lga, street_address, root_admin, plan, plan_duration, is_existing) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
      [
        paystackRef,
        name,
        userEmail,
        finalHashedPassword,
        state,
        lga,
        address,
        finalAdminName,
        planPayload,
        months,
        isExistingAdmin,
      ],
    );

    res.json({ paymentLink: response.data.data.authorization_url });
  } catch (error) {
    console.error("Registration Error:", error.response?.data || error.message);
    res.status(500).json({ error: "Registration process failed" });
  }
});

// ─── WEBHOOK ROUTE ───
router.post("/paystack-webhook", async (req, res) => {
  const secret = process.env.PAYSTACK_SECRET_TEST_KEY;

  const hash = crypto
    .createHmac("sha512", secret)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (hash !== req.headers["x-paystack-signature"]) {
    return res.sendStatus(400);
  }

  const payload = req.body;
  if (payload.event !== "charge.success") {
    return res.sendStatus(200);
  }

  const { reference } = payload.data;
  // const paystackTransactionId = payload.data.id?.toString();
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const tempUserResult = await client.query(
      "SELECT * FROM temp_payment_info WHERE tx_ref = $1",
      [reference],
    );

    if (tempUserResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.sendStatus(200);
    }

    const tempUser = tempUserResult.rows[0];
    const durationMonths = Number(tempUser.plan_duration) || 1;

    const paidAmount = payload.data.amount ? payload.data.amount / 100 : 0;
    const paymentChannel = payload.data.channel
      ? payload.data.channel.toUpperCase()
      : "CARD";

    let superAdminNotifTitle = "";
    let superAdminNotifMessage = "";
    let targetEstateId = tempUser.estate_id || null;

    if (tempUser.is_renewal || tempUser.estate_id) {
      // 1. Fetch current subscription details
      const estateRes = await client.query(
        "SELECT name, subscription_expiry, state FROM estates WHERE id = $1",
        [tempUser.estate_id],
      );

      if (estateRes.rows.length === 0) {
        throw new Error(`Estate not found for ID: ${tempUser.estate_id}`);
      }

      const currentExpiry = estateRes.rows[0].subscription_expiry
        ? new Date(estateRes.rows[0].subscription_expiry)
        : new Date();
      const startDate = new Date();

      let coverageEndDate;

      if (tempUser.is_renewal) {
        const baseDate = new Date();
        coverageEndDate = new Date(
          baseDate.setMonth(baseDate.getMonth() + durationMonths),
        );
      } else if (tempUser.is_extension) {
        const baseDate =
          currentExpiry > startDate ? new Date(currentExpiry) : new Date();
        coverageEndDate = new Date(
          baseDate.setMonth(baseDate.getMonth() + durationMonths),
        );
      } else {
        coverageEndDate = currentExpiry;
      }

      await client.query(
        `UPDATE estates 
        SET plan = $1, subscription_expiry = $2
        WHERE id = $3`,
        [tempUser.plan, coverageEndDate, tempUser.estate_id],
      );

      await client.query(
        `INSERT INTO estate_subscription_payments (
          estate_id, processed_by_email, amount, currency, plan,
          payment_method, payment_reference, payment_status, state, country,
          coverage_start_date, coverage_end_date, duration_months, gateway_metadata
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
        [
          tempUser.estate_id,
          tempUser.email,
          paidAmount,
          "NGN",
          tempUser.plan,
          paymentChannel,
          reference,
          "SUCCESSFUL",
          estateRes.rows[0].state || tempUser.state || "Lagos",
          "Nigeria",
          startDate,
          coverageEndDate,
          durationMonths,
          JSON.stringify(payload.data),
        ],
      );

      // Set notification messages dynamically based on type
      if (tempUser.is_extension) {
        superAdminNotifTitle = "Subscription Extended ⏳";
        superAdminNotifMessage = `Estate "${estateRes.rows[0].name}" extended their subscription by ${durationMonths} month(s) for ₦${paidAmount.toLocaleString()}.`;
      } else if (tempUser.is_renewal) {
        superAdminNotifTitle = "Subscription Renewed 💳";
        superAdminNotifMessage = `Estate "${estateRes.rows[0].name}" renewed their subscription for ₦${paidAmount.toLocaleString()} (${durationMonths} month(s)).`;
      } else {
        superAdminNotifTitle = "Module(s) Added 🧩";
        superAdminNotifMessage = `Estate "${estateRes.rows[0].name}" added new add-on modules for ₦${paidAmount.toLocaleString()}.`;
      }
    }
    // ─── BRANCH 2: NEW ESTATE PROVISIONING ───
    else {
      const subscriptionExpiry = new Date();
      subscriptionExpiry.setMonth(
        subscriptionExpiry.getMonth() + durationMonths,
      );

      const newEstate = await provisionEstateAccount(client, {
        tempUser,
        paidAmount,
        paymentChannel,
        reference,
        durationMonths,
        expiryDate: subscriptionExpiry,
        gatewayMetadata: payload.data,
      });

      targetEstateId = newEstate?.id || null;
      superAdminNotifTitle = "New Estate Registered 🎉";
      superAdminNotifMessage = `New estate "${tempUser.estate_name || tempUser.name}" has been registered with added plan features - ${tempUser.plan} and amount:(₦${paidAmount.toLocaleString()}).`;
    }

    const notifResult = await client.query(
      `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
       VALUES ($1, NULL, 'super_admin', $2, $3, 'general')
       RETURNING *`,
      [targetEstateId, superAdminNotifTitle, superAdminNotifMessage],
    );

    const superAdminNotification = notifResult.rows[0];

    await client.query("DELETE FROM temp_payment_info WHERE tx_ref = $1", [
      reference,
    ]);

    await client.query("COMMIT");
    io.to("superadmins").emit("new_notification", superAdminNotification);
    res.sendStatus(200);
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("❌ Webhook Processing Error:", error.message);
    res.status(500).send("Internal Server Error");
  } finally {
    client.release();
  }
});

router.get("/callback", async (req, res) => {
  const { reference } = req.query;

  if (!reference) {
    // Default fallback if no reference exists at all
    return res.redirect("https://gatemanhq.com/payment-failure");
  }

  try {
    // 1. Verify payment status with Paystack
    const response = await axios.get(
      `https://api.paystack.co/transaction/verify/${reference}`,
      {
        headers: {
          Authorization: `Bearer ${"sk_test_e15daa63d38745226220df5e74d0ff513cf7cc4c"}`,
        },
      },
    );

    const isSuccess = response.data.data.status === "success";

    // 2. Route based on the Reference Prefix
    if (reference.startsWith("RSVP_")) {
      // --- EVENT RSVP FLOW ---
      if (!isSuccess) {
        return res.redirect("https://gatemanhq.com/registration_failed");
      }

      // Check if the webhook already finished the DB work
      const regResult = await pool.query(
        "SELECT guest_code, guest_email FROM event_registrations WHERE tx_ref = $1",
        [reference],
      );

      if (regResult.rows.length > 0) {
        const code = regResult.rows[0].guest_code;
        const email = regResult.rows[0].guest_email;
        const encodedEmail = encodeURIComponent(email);
        return res.redirect(
          `https://gatemanhq.com/registration_success?code=${code}&email=${encodedEmail}`,
        );
      } else {
        // Payment is confirmed, but webhook is still processing
        return res.redirect(
          `https://gatemanhq.com/registration_success?ref=${reference}&status=pending`,
        );
      }
    } else {
      // --- STANDARD ESTATE ONBOARDING FLOW ---
      if (!isSuccess) {
        return res.redirect("https://gatemanhq.com/payment-failure");
      }
      return res.redirect(
        `https://gatemanhq.com/payment-success?ref=${reference}`,
      );
    }
  } catch (err) {
    console.error("Verification Error:", err.message);
    // Route the error to the appropriate failure page based on the ref
    const failUrl = reference.startsWith("RSVP_")
      ? "https://gatemanhq.com/registration_failed"
      : "https://gatemanhq.com/payment-failure";
    res.redirect(failUrl);
  }
});

router.use(isAuth);

router.get(
  "/pricing-config",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    console.log("billing get api hit!");
    try {
      const result = await pool.query(
        `SELECT value, updated_at FROM system_settings WHERE setting_key = 'subscription_pricing';`,
      );

      // Multi-duration tier fallback schema
      const defaultPricing = {
        base_platform_price: { ...DEFAULT_TIERS },
        modules: {
          payments: { ...DEFAULT_TIERS },
          security: { ...DEFAULT_TIERS },
          community: { ...DEFAULT_TIERS },
          facility_bookings: { ...DEFAULT_TIERS },
          services_dispatch: { ...DEFAULT_TIERS },
        },
      };

      const pricing =
        result.rows.length > 0 ? result.rows[0].value : defaultPricing;
      const updatedAt =
        result.rows.length > 0 ? result.rows[0].updated_at : null;

      return res.json({
        success: true,
        pricing,
        updated_at: updatedAt,
      });
    } catch (err) {
      console.error("Get Pricing Config Error:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to fetch active pricing configuration.",
      });
    }
  },
);

router.post(
  "/subscribe",
  ensureAdmin,
  authorizeEstate,
  verifyPermission("manage_estate_subscription", "estate_administration"),
  async (req, res) => {
    try {
      const {
        estateId,
        selectedAddOns = [],
        planDuration = 1,
        isExtension = false,
      } = req.body;
      console.log("Renewal body:", req.body);

      const userEmail = req.user?.email?.trim().toLowerCase();

      if (!estateId || !userEmail) {
        return res.status(400).json({
          error: "Estate ID and email are required",
        });
      }

      // Fetch estate details & current plan
      const estateResult = await pool.query(
        `SELECT id, name, state, lga, plan, subscription_expiry FROM estates WHERE id = $1 LIMIT 1`,
        [estateId],
      );

      if (estateResult.rows.length === 0) {
        return res.status(404).json({ error: "Estate not found" });
      }

      const estate = estateResult.rows[0];
      let currentPlan = {};
      if (typeof estate.plan === "string") {
        try {
          currentPlan = JSON.parse(estate.plan);
        } catch (e) {
          currentPlan = {};
        }
      } else if (estate.plan) {
        currentPlan = estate.plan;
      }

      const currentAddons = currentPlan.selected_add_ons || [];
      const expiryDate = estate.subscription_expiry
        ? new Date(estate.subscription_expiry)
        : null;
      const now = new Date();
      const isActive = expiryDate && expiryDate > now;

      // Determine if pure renewal/extension OR adding new modules mid-cycle
      const isRenewal = !isActive;

      // Combine current add-ons with newly selected ones
      // const finalAddOns = isRenewal
      //   ? selectedAddOns
      //   : Array.from(new Set([...currentAddons, ...selectedAddOns]));

      const months = Math.max(1, Number(planDuration) || 1);
      const tierKey = getTierKey(months);

      // Pricing Matrix
      const pricingResult = await pool.query(
        `SELECT value FROM system_settings WHERE setting_key = 'subscription_pricing'`,
      );

      const pricingMatrix =
        pricingResult.rows.length > 0
          ? typeof pricingResult.rows[0].value === "string"
            ? JSON.parse(pricingResult.rows[0].value)
            : pricingResult.rows[0].value
          : DEFAULT_PRICING_MATRIX;

      let finalAddOnsToStore = [];
      let totalCostNaira = 0;

      if (isRenewal) {
        const baseFee = getPriceForTier(
          pricingMatrix.base_platform_price,
          tierKey,
        );
        const modulesFee = selectedAddOns.reduce(
          (sum, key) =>
            sum + getPriceForTier(pricingMatrix.modules?.[key], tierKey),
          0,
        );
        totalCostNaira = (baseFee + modulesFee) * months;
        finalAddOnsToStore = selectedAddOns;
      } else if (isExtension) {
        finalAddOnsToStore = Array.from(
          new Set([...currentAddons, ...selectedAddOns]),
        );

        const baseExtensionFee = getPriceForTier(
          pricingMatrix.base_platform_price,
          tierKey,
        );
        const allModulesExtensionFee = finalAddOnsToStore.reduce(
          (sum, key) =>
            sum + getPriceForTier(pricingMatrix.modules?.[key], tierKey),
          0,
        );
        const extensionMonthlyFee = baseExtensionFee + allModulesExtensionFee;

        // 2. Calculate prorated cost for NEW add-ons over the remaining active period
        let remainingProratedFee = 0;
        if (selectedAddOns.length > 0) {
          const diffTime = expiryDate
            ? expiryDate.getTime() - now.getTime()
            : 0;
          const remainingDays = Math.max(
            0,
            Math.ceil(diffTime / (1000 * 60 * 60 * 24)),
          );
          const remainingMonths = Math.max(1, Math.ceil(remainingDays / 30));
          const remainingTierKey = getTierKey(remainingMonths);

          const newAddonsMonthlyFee = selectedAddOns.reduce(
            (sum, key) =>
              sum +
              getPriceForTier(pricingMatrix.modules?.[key], remainingTierKey),
            0,
          );

          remainingProratedFee = newAddonsMonthlyFee * remainingMonths;
        }

        totalCostNaira = extensionMonthlyFee * months + remainingProratedFee;
      } else {
        if (selectedAddOns.length === 0) {
          return res.status(400).json({
            error: "Please select at least one module to add.",
          });
        }

        finalAddOnsToStore = Array.from(
          new Set([...currentAddons, ...selectedAddOns]),
        );

        const totalMonthlyNaira = selectedAddOns.reduce(
          (sum, key) =>
            sum + getPriceForTier(pricingMatrix.modules?.[key], tierKey),
          0,
        );

        totalCostNaira = totalMonthlyNaira * months;
      }

      const amountInKobo = Math.round(totalCostNaira * 100);
      const paystackRef = `SUB_${estateId}_${Date.now()}`;
      const planPayload = {
        selected_add_ons: finalAddOnsToStore,
        is_trial: false,
      };

      // Initialize Paystack
      const paymentData = {
        email: userEmail,
        amount: amountInKobo,
        reference: paystackRef,
        callback_url: "https://gatemanhq.com/api/payment/callback",
        metadata: { estateId, isRenewal, planDuration: months },
      };

      const response = await axios.post(
        "https://api.paystack.co/transaction/initialize",
        paymentData,
        {
          headers: {
            Authorization: `Bearer sk_test_e15daa63d38745226220df5e74d0ff513cf7cc4c`,
            "Content-Type": "application/json",
          },
        },
      );

      await pool.query(
        `INSERT INTO temp_payment_info (
          tx_ref, name, email, state, lga, plan, plan_duration, is_existing, is_renewal, is_extension, estate_id
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          paystackRef,
          estate.name,
          userEmail,
          estate.state,
          estate.lga,
          planPayload,
          months,
          true,
          isRenewal,
          isExtension,
          estateId,
        ],
      );

      res.json({ paymentLink: response.data.data.authorization_url });
    } catch (error) {
      console.error(
        "Subscription Error:",
        error.response?.data || error.message,
      );
      res.status(500).json({ error: "Failed to initialize subscription" });
    }
  },
);

// POST: Upload Payment Log
router.post(
  "/upload",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("payments"),
  async (req, res) => {
    const {
      amount,
      category,
      receipt_url,
      notes,
      payment_date,
      payment_type,
      estate_id,
    } = req.body;

    const { id: resident_id, name } = req.user;

    console.log("Received payment log upload paymentdate:", payment_date);

    try {
      // 1. Fetch estate payment_items to validate category
      const estateQuery = `SELECT payment_items FROM estates WHERE id = $1`;
      const estateResult = await pool.query(estateQuery, [estate_id]);

      if (estateResult.rows.length === 0) {
        return res
          .status(404)
          .json({ success: false, error: "Estate not found" });
      }

      const availableCategories = estateResult.rows[0].payment_items || [];

      // Ensure valid string array before comparing
      const categoryList = Array.isArray(availableCategories)
        ? availableCategories
        : typeof availableCategories === "string"
          ? JSON.parse(availableCategories)
          : [];

      if (!category || !categoryList.includes(category)) {
        return res.status(400).json({
          success: false,
          error: `Invalid payment category. Must be one of: ${categoryList.join(", ")}`,
        });
      }

      // 2. Parse date safely
      const parsedPaymentDate = payment_date
        ? new Date(payment_date)
        : new Date();

      // 3. Insert record without transaction_reference
      const insertQuery = `
      INSERT INTO payment_logs 
      (resident_id, estate_id, amount, category, receipt_url, notes, resident_name, payment_date, payment_type, status) 
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'pending') 
      RETURNING *`;

      const result = await pool.query(insertQuery, [
        resident_id,
        estate_id,
        amount,
        category,
        receipt_url,
        notes,
        name,
        parsedPaymentDate,
        payment_type,
      ]);

      const newPaymentLog = result.rows[0];

      // 4. Respond immediately
      res.status(201).json({ success: true, data: newPaymentLog });

      // 5. Derive dynamic metadata and trigger audit log asynchronously
      const categoryNamespace = category.toUpperCase().trim();
      const dynamicActionType = `${categoryNamespace}_PAYMENT_UPLOADED`;

      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: dynamicActionType,
        target_resource: "payment_logs",
        target_id: newPaymentLog.id,
        description: `Resident "${name}" uploaded a pending ${category.toLowerCase()} payment proof of ₦${amount}.`,
        state_before: null,
        state_after: newPaymentLog,
        urgency: "MEDIUM",
      });
    } catch (error) {
      console.error("Payment Upload Error:", error);
      res.status(500).json({ success: false, error: error.message });
    }
  },
);

// GET: Fetch History with Date Filtering
router.post(
  "/history",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("payments"),
  async (req, res) => {
    const { startDate, endDate } = req.query;
    const { estate_id } = req.body;
    console.log("Fetching history with filters:", { startDate, endDate });
    const { id: resident_id } = req.user;
    console.log("Fetching history form", estate_id);

    try {
      let query = `SELECT * FROM payment_logs WHERE resident_id = $1 AND estate_id = $2`;
      const params = [resident_id, estate_id];

      if (startDate && endDate) {
        query += ` AND payment_date::DATE BETWEEN $3 AND $4`;
        params.push(startDate, endDate);
      }

      query += ` ORDER BY created_at DESC`;

      const result = await pool.query(query, params);
      res.json({ success: true, history: result.rows });
    } catch (error) {
      res
        .status(500)
        .json({ success: false, error: "Failed to fetch history" });
    }
  },
);

// GET: Fetch all estate payments for frontend-side filtering
router.get(
  "/all-payments/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("payments"),
  verifyPermission("view_estate_records", "estate_administration"),
  async (req, res) => {
    const estate_id = req.params.id;

    if (!estate_id) {
      return res.status(401).json({ success: false, error: "Unauthorized" });
    }

    try {
      const query = `SELECT * FROM payment_logs WHERE estate_id = $1 ORDER BY created_at DESC`;
      const result = await pool.query(query, [estate_id]);

      res.json({
        success: true,
        payments: result.rows,
      });
    } catch (error) {
      console.error("Admin fetch payments error:", error);
      res.status(500).json({ success: false, error: "Internal server error" });
    }
  },
);

// URL: /api/payment/verify/:id
router.patch(
  "/verify/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("payments"),
  verifyPermission("modify_records_status", "estate_administration"),
  async (req, res) => {
    const { id } = req.params;
    const { status, estate_id } = req.body;

    // 1. Validation
    if (!["verified", "rejected"].includes(status)) {
      return res.status(400).json({
        success: false,
        error: "Invalid status. Must be 'verified' or 'rejected'.",
      });
    }

    try {
      // 🧠 Fetch the pre-existing state before committing changes
      const initialCheck = await pool.query(
        `SELECT * FROM payment_logs WHERE id = $1 AND estate_id = $2`,
        [id, estate_id],
      );

      if (initialCheck.rowCount === 0) {
        return res.status(404).json({
          success: false,
          error: "Payment record not found or unauthorized.",
        });
      }

      const stateBefore = initialCheck.rows[0];

      // 2. Execute Update
      const query = `
      UPDATE payment_logs 
      SET status = $1, verified_at = NOW()
      WHERE id = $2 AND estate_id = $3
      RETURNING *`;

      const result = await pool.query(query, [status, id, estate_id]);
      const stateAfter = result.rows[0];

      // 3. Return Response to Client immediately
      res.json({
        success: true,
        message: `Payment ${status} successfully`,
        data: stateAfter,
      });

      // 4. Trace Footprint Async (Fails safely internally without impeding response)
      const actionVerb =
        status === "verified" ? "PAYMENT_VERIFIED" : "PAYMENT_REJECTED";
      const urgencyLevel = status === "verified" ? "INFO" : "WARNING";

      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: actionVerb,
        target_resource: "payment_logs",
        target_id: id,
        description: `Admin processed this payment and toggled state to ${status.toUpperCase()}.`,
        state_before: stateBefore,
        state_after: stateAfter,
        urgency: urgencyLevel,
      });
    } catch (error) {
      console.error("Verification Error:", error);
      res.status(500).json({
        success: false,
        error: "Internal server error",
      });
    }
  },
);

// DELETE: Remove a log (only if still pending)
router.delete("/delete/:id", async (req, res) => {
  try {
    // console.log(
    //   `Attempting to delete log ID ${req.params.id} for resident ID ${req.user.id}`,
    // );

    // Using RETURNING * is perfect here because it captures the data right as it drops
    const query = `
      DELETE FROM payment_logs 
      WHERE id = $1 AND resident_id = $2 AND status = 'pending' 
      RETURNING *`;

    const result = await pool.query(query, [req.params.id, req.user.id]);

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ success: false, message: "Log not found or already verified" });
    }

    const deletedRecord = result.rows[0];

    // 1. Respond to the resident app instantly
    res.json({ success: true, message: "Deleted successfully" });

    // 2. Fire the audit log footprints safely in the background
    await createAppAuditLog(req, {
      estate_id: req.user.estate_id,
      action_type: "PENDING_PAYMENT_DELETED",
      target_resource: "payment_logs",
      target_id: req.params.id,
      description: `Resident deleted pending payment log entry ID ${req.params.id} for reference "${deletedRecord.reference || "N/A"}".`,
      state_before: deletedRecord, // Preserves the raw data that was just destroyed
      state_after: null, // Intentionally null since the row no longer exists
      urgency: "INFO",
    });
  } catch (error) {
    console.error("Deletion Error:", error);
    res.status(500).json({ success: false, error: error.message });
  }
});

router.get(
  "/payment-items/:estate_id",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("payments"),
  async (req, res) => {
    const { estate_id } = req.params;

    if (!estate_id) {
      return res.status(400).json({
        success: false,
        error: "Missing required parameter: estate_id",
      });
    }

    try {
      const query = `
        SELECT id, name, payment_items 
        FROM estates 
        WHERE id = $1;
      `;

      const { rows } = await pool.query(query, [estate_id]);

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Estate record not found",
        });
      }

      const estate = rows[0];

      return res.status(200).json({
        success: true,
        payment_items: estate.payment_items || [],
      });
    } catch (err) {
      console.error("Error fetching payment items:", err);
      return res.status(500).json({
        success: false,
        error: "Internal server error fetching payment items configuration.",
      });
    }
  },
);

export default router;
