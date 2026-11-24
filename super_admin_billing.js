import express from "express";
import pool from "./db.js";
import {
  isAuth,
  isSuperAdmin,
  verifyPermission,
} from "./middlewares.js";
import { createAuditLog } from "./helpers.js";
import {
  sendAdminWelcomeEmail,
  sendPasswordResetCode,
  sendRegistrationOTP,
} from "./emailService.js";
import { loadPoliciesIntoMemory, getCachedPolicies } from "./policyCache.js";

const router = express.Router();
router.use(isSuperAdmin);
router.use(isAuth);

// ─── 1. FETCH AGGREGATED BILLING ANALYTICS & SUBSCRIPTION METRICS ───
router.get(
  "/analytics",
  verifyPermission("view_financials", "billing_management"),
  async (req, res) => {
    try {
      // 1. Estate Health Stats (Active vs Expired vs Expiring in 7 days)
      const estateStatsQuery = pool.query(`
        SELECT 
          COUNT(*)::INT AS total_estates,
          COUNT(*) FILTER (WHERE subscription_expiry > NOW())::INT AS active_estates,
          COUNT(*) FILTER (WHERE subscription_expiry <= NOW() OR subscription_expiry IS NULL)::INT AS expired_estates,
          COUNT(*) FILTER (WHERE subscription_expiry BETWEEN NOW() AND NOW() + INTERVAL '7 days')::INT AS expiring_soon
        FROM public.estates;
      `);

      // 2. All Monthly Revenue History (Grouped by Year & Month)
      const monthlyPaymentsQuery = pool.query(`
        SELECT 
          EXTRACT(YEAR FROM created_at)::INT AS year,
          EXTRACT(MONTH FROM created_at)::INT AS month,
          TO_CHAR(DATE_TRUNC('month', created_at), 'Mon') AS month_name,
          COALESCE(SUM(amount), 0)::FLOAT AS total_amount,
          COUNT(id)::INT AS total_transactions
        FROM public.estate_subscription_payments
        WHERE payment_status = 'SUCCESSFUL'
        GROUP BY EXTRACT(YEAR FROM created_at), EXTRACT(MONTH FROM created_at), DATE_TRUNC('month', created_at)
        ORDER BY year DESC, month DESC;
      `);

      // 3. Feature Distribution Breakdown (Unnested selected_add_ons)
      const featureDistributionQuery = pool.query(`
        SELECT 
          feature_name,

          -- Active paid estates (Not trial AND Expiry in future)
          COUNT(DISTINCT CASE 
            WHEN e.subscription_expiry > NOW() 
            AND (
              (e.plan::jsonb->>'is_trial')::boolean IS NOT TRUE
            )
            THEN e.id 
          END)::INT AS active_estates,

          -- Active trial estates (Trial AND Expiry in future)
          COUNT(DISTINCT CASE 
            WHEN e.subscription_expiry > NOW() 
            AND (
              (e.plan::jsonb->>'is_trial')::boolean IS TRUE
            )
            THEN e.id 
          END)::INT AS trial_estates,

          -- Expired estates that had this feature
          COUNT(DISTINCT CASE 
            WHEN e.subscription_expiry <= NOW() OR e.subscription_expiry IS NULL 
            THEN e.id 
          END)::INT AS expired_estates,

          -- Total estates on record with this feature
          COUNT(DISTINCT e.id)::INT AS total_estates

        FROM public.estates e,
        LATERAL jsonb_array_elements_text(
          CASE 
            WHEN jsonb_typeof(
              CASE 
                WHEN jsonb_typeof(e.plan::jsonb) = 'string' THEN (e.plan::jsonb)::jsonb->'selected_add_ons'
                ELSE e.plan::jsonb->'selected_add_ons'
              END
            ) = 'array' 
            THEN 
              CASE 
                WHEN jsonb_typeof(e.plan::jsonb) = 'string' THEN (e.plan::jsonb)::jsonb->'selected_add_ons'
                ELSE e.plan::jsonb->'selected_add_ons'
              END
            ELSE '[]'::jsonb 
          END
        ) AS feature_name

        GROUP BY feature_name
        ORDER BY active_estates DESC;
      `);

      // 4. Regional Revenue (By State)
      const stateBreakdownQuery = pool.query(`
        SELECT 
          state,
          COALESCE(SUM(amount), 0)::FLOAT AS total_revenue,
          COUNT(DISTINCT estate_id)::INT AS active_estates
        FROM public.estate_subscription_payments
        WHERE payment_status = 'SUCCESSFUL'
        GROUP BY state
        ORDER BY total_revenue DESC;
      `);

      const [
        estateStats,
        monthlyPayments,
        featureDistribution,
        stateBreakdown,
      ] = await Promise.all([
        estateStatsQuery,
        monthlyPaymentsQuery,
        featureDistributionQuery,
        stateBreakdownQuery,
      ]);

      return res.json({
        success: true,
        stats: estateStats.rows[0] || {
          total_estates: 0,
          active_estates: 0,
          expired_estates: 0,
          expiring_soon: 0,
        },
        monthly_history: monthlyPayments.rows,
        feature_distribution: featureDistribution.rows,
        regional_breakdown: stateBreakdown.rows,
      });
    } catch (err) {
      console.error("Fetch Billing Analytics Error:", err);
      return res.status(500).json({
        success: false,
        message: "Error fetching billing analytics.",
      });
    }
  },
);

// ─── 2. FETCH ALL ESTATE SUBSCRIPTIONS & LEDGER ───
router.get(
  "/subscriptions",
  verifyPermission("view_financials", "billing_management"),
  async (req, res) => {
    try {
      const subscriptionsQuery = pool.query(`
        SELECT 
          id, 
          name, 
          estate_code, 
          plan, 
          subscription_expiry, 
          CASE 
            WHEN subscription_expiry IS NULL THEN 'EXPIRED'
            WHEN subscription_expiry >= NOW() THEN 'ACTIVE'
            ELSE 'EXPIRED'
          END AS subscription_status, 
          created_at
        FROM public.estates
        ORDER BY subscription_expiry ASC NULLS LAST;
      `);

      // 2. Ledger Tab Data (Full payment audit trail with estate context)
      const paymentsLedgerQuery = pool.query(`
        SELECT 
          p.id,
          p.estate_id,
          e.name AS estate_name,
          e.estate_code,
          p.processed_by_email,
          p.amount,
          p.currency,
          p.plan,
          p.payment_method,
          p.payment_reference,
          p.payment_status,
          p.state,
          p.country,
          p.coverage_start_date,
          p.coverage_end_date,
          p.duration_months,
          p.gateway_metadata,
          p.created_at
        FROM public.estate_subscription_payments p
        LEFT JOIN public.estates e ON p.estate_id = e.id
        ORDER BY p.created_at DESC;
      `);

      const [subscriptionsResult, ledgerResult] = await Promise.all([
        subscriptionsQuery,
        paymentsLedgerQuery,
      ]);

      return res.json({
        success: true,
        subscriptions: subscriptionsResult.rows,
        payments_ledger: ledgerResult.rows,
      });
    } catch (err) {
      console.error("Fetch Subscriptions & Ledger Error:", err);
      return res.status(500).json({
        success: false,
        message: "Error retrieving estate subscriptions and payment ledger.",
      });
    }
  },
);

const REQUIRED_MODULES = [
  "payments",
  "security",
  "community",
  "facility_bookings",
  "services_dispatch",
];

const DURATION_TIERS = [
  "monthly",
  "six_months",
  "twelve_months",
  "twenty_four_months",
];

const DEFAULT_TIERS = {
  monthly: 0,
  six_months: 0,
  twelve_months: 0,
  twenty_four_months: 0,
};

// Helper to validate duration tier objects
const isValidTierObject = (obj) => {
  if (!obj || typeof obj !== "object") return false;
  return DURATION_TIERS.every(
    (tier) => typeof obj[tier] === "number" && obj[tier] >= 0,
  );
};

// ─── 1. GET PRICING CONFIGURATION ───
router.get(
  "/pricing-config",
  verifyPermission(["manage_pricing", "view_financials"], "billing_management"),
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

// ─── 2. UPDATE FEATURE-BASED PRICING CONFIGURATION ───
router.put(
  "/pricing-config",
  verifyPermission("manage_pricing", "billing_management"),
  async (req, res) => {
    console.log("billing put api hit!");
    const { base_platform_price, modules } = req.body;

    // Validate Base Platform Price Tiers
    if (!isValidTierObject(base_platform_price)) {
      return res.status(400).json({
        success: false,
        message:
          "Invalid payload. 'base_platform_price' must be an object with non-negative numbers for: monthly, six_months, twelve_months, and twenty_four_months.",
      });
    }

    // Validate Modules Payload
    if (!modules || typeof modules !== "object") {
      return res.status(400).json({
        success: false,
        message: "Invalid payload. 'modules' payload object is required.",
      });
    }

    for (const key of REQUIRED_MODULES) {
      if (!isValidTierObject(modules[key])) {
        return res.status(400).json({
          success: false,
          message: `Invalid price structure for module '${key}'. Must contain non-negative numbers for all duration tiers.`,
        });
      }
    }

    try {
      const updatedPricing = {
        base_platform_price: {
          monthly: base_platform_price.monthly,
          six_months: base_platform_price.six_months,
          twelve_months: base_platform_price.twelve_months,
          twenty_four_months: base_platform_price.twenty_four_months,
        },
        modules: {
          payments: { ...modules.payments },
          security: { ...modules.security },
          community: { ...modules.community },
          facility_bookings: { ...modules.facility_bookings },
          services_dispatch: { ...modules.services_dispatch },
        },
      };

      const result = await pool.query(
        `INSERT INTO system_settings (setting_key, value, updated_at, updated_by)
         VALUES ('subscription_pricing', $1::jsonb, CURRENT_TIMESTAMP, $2)
         ON CONFLICT (setting_key) 
         DO UPDATE SET 
           value = EXCLUDED.value,
           updated_at = EXCLUDED.updated_at,
           updated_by = EXCLUDED.updated_by
         RETURNING value;`,
        [JSON.stringify(updatedPricing), req.user.id],
      );

      await createAuditLog(req, {
        action_type: "UPDATE_SUBSCRIPTION_PRICING",
        target_resource: "system_settings",
        target_id: "subscription_pricing",
        description: `Updated multi-duration modular pricing matrix.`,
        state_before: null,
        state_after: updatedPricing,
        log_type: "financial",
      });

      return res.json({
        success: true,
        message: "Global feature pricing matrix updated successfully.",
        pricing: result.rows[0].value,
      });
    } catch (err) {
      console.error("Update Pricing Config Error:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to update pricing configurations.",
      });
    }
  },
);

// ─── 4. MANUAL SUBSCRIPTION EXTENSION / RENEWAL ───
router.post(
  "/manual-renew",
  verifyPermission("manage_subscription", "billing_management"),
  async (req, res) => {
    const { estate_id, duration_months } = req.body;

    if (!estate_id || !duration_months) {
      return res
        .status(400)
        .json({ success: false, message: "Estate ID and duration required." });
    }

    try {
      const updateResult = await pool.query(
        `UPDATE public.estates 
         SET subscription_expiry = COALESCE(
           CASE WHEN subscription_expiry > NOW() THEN subscription_expiry ELSE NOW() END, 
           NOW()
         ) + ($1 || ' months')::INTERVAL
         WHERE id = $2
         RETURNING id, name, subscription_expiry;`,
        [duration_months, estate_id],
      );

      const updatedEstate = updateResult.rows[0];

      await createAuditLog(req, {
        action_type: "MANUAL_SUBSCRIPTION_EXTENSION",
        target_resource: "estates",
        target_id: estate_id,
        description: `Extended subscription for ${updatedEstate.name} by ${duration_months} month(s).`,
        state_before: null,
        state_after: updatedEstate,
        log_type: "financial",
      });

      return res.json({
        success: true,
        message: `Subscription extended for ${updatedEstate.name}`,
        estate: updatedEstate,
      });
    } catch (err) {
      console.error("Manual Renew Error:", err);
      return res.status(500).json({
        success: false,
        message: "Error extending estate subscription.",
      });
    }
  },
);

export default router;
