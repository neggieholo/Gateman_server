import express from "express";
import bcrypt from "bcrypt";
import axios from "axios";
import pool from "./db.js";
import crypto from "crypto";
import {
  isAuth,
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";

const router = express.Router();

router.use(isAuth);

router.get(
  "/admin-stats/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    const estate_id = req.params.id;
    const admin_id = req.user.id;

    try {
      // 1. Fetch estate subscription plan to check enabled add-ons
      const planRes = await pool.query(
        "SELECT plan FROM estates WHERE id = $1",
        [estate_id],
      );

      const plan = planRes.rows[0] || { is_trial: false, selected_add_ons: [] };
      const isTrial = plan.is_trial;
      const addOns = plan.selected_add_ons || [];

      const isEnabled = (key) => isTrial || addOns.includes(key);

      // 2. Prepare conditional DB queries
      const securityPromise = isEnabled("security")
        ? Promise.all([
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
          ])
        : Promise.resolve(null);

      const communityPromise = isEnabled("community")
        ? pool.query(
            `SELECT COUNT(*) FILTER (WHERE is_archived = false) as total_alerts,
                    COUNT(*) FILTER (WHERE admin_seen = false AND is_archived = false) as unread
             FROM posts WHERE estate_id = $1`,
            [estate_id],
          )
        : Promise.resolve(null);

      const paymentsPromise = isEnabled("payments")
        ? Promise.all([
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
          ])
        : Promise.resolve(null);

      const eventsPromise = isEnabled("facility_bookings")
        ? pool.query(
            `SELECT 
              COUNT(*) as total_bookings,
              COUNT(*) FILTER (WHERE status= 'PENDING_APPROVAL') as pending_bookings,
              COUNT(*) FILTER (WHERE status= 'PAYMENT_PENDING') as payment_pending_bookings,
              COUNT(*) FILTER (WHERE status= 'PAYMENT_SUBMITTED') as payment_submitted_bookings,
              COUNT(*) FILTER (WHERE status= 'APPROVED') as approved_bookings,
              (SELECT json_build_object('resident_name', tu.name, 'venue_name', lb.venue_name, 'date', lb.start_date) 
               FROM location_bookings lb
               LEFT JOIN tenant_users tu ON tu.id = lb.resident_id
               WHERE lb.estate_id = $1 
                 AND lb.start_date >= CURRENT_DATE 
                 AND lb.status = 'APPROVED' 
               ORDER BY start_date ASC, start_time ASC 
               LIMIT 1) as nearest_booking
             FROM location_bookings 
             WHERE estate_id = $1`,
            [estate_id],
          )
        : Promise.resolve(null);

      const servicesPromise = isEnabled("services_dispatch")
        ? pool.query(
            `SELECT 
            COUNT(*) as total_requests,
            COUNT(*) FILTER (WHERE is_dispatched = false AND is_completed = false) as pending_requests,
            COUNT(*) FILTER (WHERE is_dispatched = true AND is_completed = false) as dispatched_requests,
            COUNT(*) FILTER (WHERE is_completed = true) as completed_requests,
            COUNT(*) FILTER (
              WHERE is_completed = true 
              AND requested_at > COALESCE(
                (SELECT last_login FROM estate_admin_users WHERE id = $2), 
                '1970-01-01'::timestamp
              )
            ) as recently_completed_requests
          FROM service_requests 
          WHERE estate_id = $1`,
            [estate_id, admin_id],
          )
        : Promise.resolve(null);

      // Core resident stats are always fetched
      const residentsPromise = Promise.all([
        pool.query(
          "SELECT COUNT(*) FROM tenant_users WHERE $1 = ANY(estate_ids)",
          [estate_id],
        ),
        pool.query(
          "SELECT COUNT(*) FROM estate_reports WHERE estate_id = $1 AND type = 'GENERAL' AND status = 'PENDING'",
          [estate_id],
        ),
        pool.query("SELECT COUNT(*) FROM join_requests WHERE estate_id = $1", [
          estate_id,
        ]),
      ]);

      // 3. Execute queries in parallel
      const [
        securityRes,
        communityRes,
        paymentsRes,
        eventsRes,
        servicesRes,
        residentsRes,
      ] = await Promise.all([
        securityPromise,
        communityPromise,
        paymentsPromise,
        eventsPromise,
        servicesPromise,
        residentsPromise,
      ]);

      // 4. Build response object with fallback zeroes for disabled modules
      res.json({
        success: true,
        data: {
          security: securityRes
            ? {
                total: parseInt(securityRes[0].rows[0].total) || 0,
                onDuty: parseInt(securityRes[0].rows[0].on_duty) || 0,
                complaints: parseInt(securityRes[1].rows[0].count) || 0,
                pendingRequests: parseInt(securityRes[2].rows[0].count) || 0,
              }
            : { total: 0, onDuty: 0, complaints: 0, pendingRequests: 0 },

          community: communityRes
            ? {
                totalAlerts: parseInt(communityRes.rows[0].total_alerts) || 0,
                unreadAlerts: parseInt(communityRes.rows[0].unread) || 0,
              }
            : { totalAlerts: 0, unreadAlerts: 0 },

          payments: paymentsRes
            ? {
                monthlyCount: parseInt(paymentsRes[0].rows[0].month_count) || 0,
                pendingPayments:
                  parseInt(paymentsRes[0].rows[0].pending_count) || 0,
                paymentReports: parseInt(paymentsRes[1].rows[0].count) || 0,
              }
            : { monthlyCount: 0, pendingPayments: 0, paymentReports: 0 },

          events: eventsRes
            ? {
                total: parseInt(eventsRes.rows[0].total_bookings) || 0,
                pending: parseInt(eventsRes.rows[0].pending_bookings) || 0,
                paymentPending:
                  parseInt(eventsRes.rows[0].payment_pending_bookings) || 0,
                paymentSubmitted:
                  parseInt(eventsRes.rows[0].payment_submitted_bookings) || 0,
                approved: parseInt(eventsRes.rows[0].approved_bookings) || 0,
                upcoming: eventsRes.rows[0].nearest_booking || {
                  resident_name: "None",
                  venue_name: "None",
                  date: null,
                },
              }
            : {
                total: 0,
                pending: 0,
                paymentPending: 0,
                paymentSubmitted: 0,
                approved: 0,
                upcoming: {
                  resident_name: "None",
                  venue_name: "None",
                  date: null,
                },
              },

          services: servicesRes
            ? {
                total: parseInt(servicesRes.rows[0].total_requests) || 0,
                pending: parseInt(servicesRes.rows[0].pending_requests) || 0,
                dispatched:
                  parseInt(servicesRes.rows[0].dispatched_requests) || 0,
                completed:
                  parseInt(servicesRes.rows[0].completed_requests) || 0,
                recentlyCompleted:
                  parseInt(servicesRes.rows[0].recently_completed_requests) ||
                  0,
              }
            : {
                total: 0,
                pending: 0,
                dispatched: 0,
                completed: 0,
                recentlyCompleted: 0,
              },

          residents: {
            total: parseInt(residentsRes[0].rows[0].count) || 0,
            complaints: parseInt(residentsRes[1].rows[0].count) || 0,
            pendingRequests: parseInt(residentsRes[2].rows[0].count) || 0,
          },
        },
      });
    } catch (err) {
      console.error("Dashboard Stats Error:", err);
      res.status(500).json({ error: "Failed to fetch dashboard statistics" });
    }
  },
);

export default router;
