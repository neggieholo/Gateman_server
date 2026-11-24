import express from "express";
import pool from "./db.js";
import { io } from "./server.js";
import {
  isAuth,
  isSuperAdmin,
  verifyPermission,
} from "./middlewares.js";
import { createAuditLog } from "./helpers.js";

const router = express.Router();
router.use(isAuth);
router.use(isSuperAdmin);

router.get(
  "/estates-directory",
  verifyPermission("view_estate_info", "estates_management"),
  async (req, res, next) => {
    try {
      const directoryQuery = `
        SELECT 
          e.id,
          e.name,
          e.estate_code,
          e.lga,
          e.state,
          e.status,
          e.created_at as joined_date,
          
          -- Correlated analytical counts (fallback safely to 0 using COALESCE)
          COALESCE((
            SELECT COUNT(r.id)::int 
            FROM tenant_users r 
            WHERE r.estate_ids @> ARRAY[e.id]
          ), 0) AS total_residents,
          
          COALESCE((
            SELECT COUNT(r_active.id)::int 
            FROM tenant_users r_active 
            WHERE r_active.estate_ids @> ARRAY[e.id] 
              AND r_active.last_activity_at >= NOW() - INTERVAL '30 days'
          ), 0) AS active_residents_30_days,
          
          COALESCE((
            SELECT COUNT(g.id)::int 
            FROM security_users g 
            WHERE g.estate_id = e.id
          ), 0) AS total_guards,
          
          COALESCE((
            SELECT COUNT(g_duty.id)::int 
            FROM security_users g_duty 
            WHERE g_duty.estate_id = e.id 
              AND g_duty.is_on_duty = 'true'
          ), 0) AS guards_on_duty
          
        FROM estates e
        ORDER BY e.created_at DESC;
      `;

      const { rows } = await pool.query(directoryQuery);

      return res.json({
        success: true,
        count: rows.length,
        estates: rows,
      });
    } catch (err) {
      console.error("Estates Directory Analytical Engine Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to assemble organizational nodes database context.",
      });
    }
  },
);

router.post(
  "/details",
  verifyPermission("view_estate_info", "estates_management"),
  async (req, res, next) => {
    try {
      const { estateId } = req.body;

      if (!estateId) {
        return res.status(400).json({
          success: false,
          message: "Missing required parameter: estateId",
        });
      }

      const baseProfileQuery = `
      SELECT 
        e.id,
        e.name,
        e.estate_code,
        e.lga,
        e.state,
        e.status,
        e.subscription_expiry,
        e.created_at as joined_date,
        COALESCE((
          SELECT COUNT(r.id)::int 
          FROM tenant_users r 
          WHERE r.estate_ids @> ARRAY[e.id]::uuid[] -- cast to match your PK type if UUID
        ), 0) AS total_residents,
        COALESCE((
          SELECT COUNT(r_active.id)::int 
          FROM tenant_users r_active 
          WHERE r_active.estate_ids @> ARRAY[e.id]::uuid[] 
            AND r_active.last_activity_at >= NOW() - INTERVAL '30 days'
        ), 0) AS active_residents_30_days,
        COALESCE((
          SELECT COUNT(g.id)::int 
          FROM security_users g 
          WHERE g.estate_id = e.id
        ), 0) AS total_guards,
        COALESCE((
          SELECT COUNT(g_duty.id)::int 
          FROM security_users g_duty 
          WHERE g_duty.estate_id = e.id 
            AND g_duty.is_on_duty = true
        ), 0) AS guards_on_duty
      FROM estates e
      WHERE e.id = $1;
    `;

      // Execute database pooling operations concurrently
      const [
        profileRes,
        gatepassesRes,
        postsRes,
        bookingsRes,
        reportsRes,
        locationsRes,
        servicesRes,
        vendorsRes,
        serviceRequestsRes,
        adminsRes,
        paymentRes,
        rootAdminRes,
        estateRes,
      ] = await Promise.all([
        pool.query(baseProfileQuery, [estateId]),
        pool.query(
          `SELECT * FROM invitations WHERE estate_id = $1 ORDER BY created_at DESC`,
          [estateId],
        ),
        pool.query(
          `SELECT * FROM posts WHERE estate_id = $1 ORDER BY created_at DESC`,
          [estateId],
        ),
        pool.query(
          `SELECT lb.*, t.name AS resident_name FROM location_bookings lb JOIN tenant_users t ON lb.resident_id = t.id WHERE estate_id = $1 ORDER BY start_time ASC`,
          [estateId],
        ),
        pool.query(
          `SELECT * FROM estate_reports WHERE estate_id = $1 ORDER BY created_at DESC`,
          [estateId],
        ),
        pool.query(
          `SELECT * FROM estate_locations WHERE estate_id = $1 ORDER BY name ASC`,
          [estateId],
        ),
        pool.query(
          `SELECT * FROM estate_services WHERE estate_id = $1 ORDER BY service_name ASC`,
          [estateId],
        ),

        pool.query(
          `SELECT * FROM estate_vendors WHERE estate_id = $1 ORDER BY created_at DESC`,
          [estateId],
        ),
        pool.query(
          `SELECT * FROM service_requests WHERE estate_id = $1 ORDER BY requested_at DESC`,
          [estateId],
        ),
        pool.query(
          `SELECT * FROM estate_admin_users WHERE $1 = ANY(estate_ids)`,
          [estateId],
        ),
        pool.query(`SELECT * FROM payment_logs WHERE estate_id = $1`, [
          estateId,
        ]),
        pool.query(`SELECT root_admin_email FROM estates WHERE id = $1`, [
          estateId,
        ]),
        pool.query(`SELECT * FROM estates WHERE id = $1`, [estateId]),
      ]);

      if (profileRes.rows.length === 0) {
        return res
          .status(404)
          .json({ success: false, message: "Estate context node not found." });
      }

      return res.json({
        success: true,
        estate: {
          ...profileRes.rows[0],
          gatepasses: gatepassesRes.rows,
          posts: postsRes.rows,
          bookings: bookingsRes.rows,
          reports: reportsRes.rows,
          locations: locationsRes.rows,
          services: servicesRes.rows,
          vendors: vendorsRes.rows,
          service_requests: serviceRequestsRes.rows,
          admins: adminsRes.rows || [],
          payment_logs: paymentRes.rows,
          root_admin_email: rootAdminRes.rows[0]?.root_admin_email || null,
          estate: estateRes.rows[0],
        },
      });
    } catch (err) {
      console.error(
        "Critical Estate Deep Inspection Extraction Engine Failure:",
        err,
      );
      return res.status(500).json({
        success: false,
        message:
          "Failed to assemble extended structural metadata scopes from operational tables.",
      });
    }
  },
);

router.post(
  "/update-admin-status",
  verifyPermission("modify_estate_admin_status", "estates_management"),
  async (req, res, next) => {
    try {
      const { adminId, status } = req.body;

      // 1. Guard Clauses & Input Validation Validation
      if (!adminId || !status) {
        return res.status(400).json({
          success: false,
          message:
            "Missing required query parameters: adminId and status target context.",
        });
      }

      const validStatuses = ["ACTIVE", "SUSPENDED"];
      if (!validStatuses.includes(status.toUpperCase())) {
        return res.status(400).json({
          success: false,
          message: "Invalid status value configuration paradigm requested.",
        });
      }

      // 2. Perform Single-Pass Conditional Update Atomicity
      const updateQuery = `
        UPDATE estate_admin_users 
        SET status = $1, updated_at = NOW()
        WHERE id = $2
        RETURNING id, name, status, email, updated_at;
      `;

      const { rows } = await pool.query(updateQuery, [
        status.toUpperCase(),
        adminId,
      ]);

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Specified asset node admin configuration matrix context not found.",
        });
      }

      await createAuditLog(req, {
        log_type: "estate_admin",
        action_type: "ESTATE_ADMIN_STATUS_UPDATE",
        target_resource: "estate_admin_users",
        target_id: adminId,
        description: `Admin access parameter updated to ${status} successfully.`,
        state_before: rows[0],
        state_after: { ...rows[0], status: status.toUpperCase() },
      });

      // 3. Dispatch Operation Feedback Pipeline
      return res.json({
        success: true,
        message: `Admin access parameter updated to ${status} successfully.`,
        admin: rows[0],
      });
    } catch (err) {
      console.error("Critical Admin Status Pipeline Exception:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal transactional pipeline engine crash mapping access tokens.",
      });
    }
  },
);

// ─── 1. SUSPEND / ACTIVATE ESTATE ACCOUNT PIPELINE ───
router.post(
  "/update-estate-status",
  verifyPermission("modify_estate_status", "estates_management"),
  async (req, res, next) => {
    try {
      const { estateId, status } = req.body;

      if (!estateId || !status) {
        return res.status(400).json({
          success: false,
          message: "Missing required query parameter payload tracking nodes.",
        });
      }

      const normalizedStatus = status.toUpperCase();
      if (!["ACTIVE", "SUSPENDED"].includes(normalizedStatus)) {
        return res.status(400).json({
          success: false,
          message:
            "Invalid status parameters targeted for deployment mutation.",
        });
      }

      const query = `
        UPDATE estates 
        SET status = $1
        WHERE id = $2 
        RETURNING id, name, status;
      `;
      const { rows } = await pool.query(query, [normalizedStatus, estateId]);

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message:
            "Target infrastructure node not found in relational lookup tables.",
        });
      }

      await createAuditLog(req, {
        log_type: "estate",
        action_type: "ESTATE_STATUS_UPDATE",
        target_resource: "estates",
        target_id: estateId,
        description: `Estate status updated to ${normalizedStatus} successfully.`,
        state_before: rows[0],
        state_after: { ...rows[0], status: normalizedStatus },
      });

      return res.json({
        success: true,
        message: `Estate system authorization state mutated to ${normalizedStatus} successfully.`,
        estate: rows[0],
      });
    } catch (err) {
      console.error("Critical Estate Suspension Pipeline Exception:", err);
      return res.status(500).json({
        success: false,
        message:
          "Internal transactional processing error tracking system status state.",
      });
    }
  },
);

// ─── 2. PURGE / DELETE ESTATE ARCHITECTURE CONTEXT ───
router.post(
  "/purge-estate-account",
  verifyPermission("delete_estate", "estates_management"),
  async (req, res, next) => {
    try {
      const { estateId } = req.body;

      if (!estateId) {
        return res.status(400).json({
          success: false,
          message: "Missing parameter: estateId",
        });
      }

      // Single atomic operation mapping across all tracking vectors
      const megaPurgeQuery = `
        WITH 
          del_admins     AS (DELETE FROM estate_admin_users WHERE estate_id = $1),
          del_security   AS (DELETE FROM security_users WHERE estate_id = $1),
          del_passes     AS (DELETE FROM gatepasses WHERE estate_id = $1),
          del_invites    AS (DELETE FROM invitations WHERE estate_id = $1),
          del_posts      AS (DELETE FROM posts WHERE estate_id = $1),
          del_services   AS (DELETE FROM services WHERE estate_id = $1),
          del_requests   AS (DELETE FROM service_requests WHERE estate_id = $1),
          del_locations  AS (DELETE FROM locations WHERE estate_id = $1),
          del_events     AS (DELETE FROM events WHERE estate_id = $1)
        DELETE FROM estates WHERE id = $1 RETURNING name;
      `;

      const { rows } = await pool.query(megaPurgeQuery, [estateId]);

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Target estate not found.",
        });
      }

      await createAuditLog(req, {
        log_type: "estate",
        action_type: "ESTATE_PURGE",
        target_resource: "estates",
        target_id: estateId,
        description: `Estate and all associated records purged successfully.`,
        state_before: rows[0],
        state_after: null,
        urgency: "high",
      });

      return res.json({
        success: true,
        message: `System cluster node "${rows[0].name}" and all cascading relational records were completely purged.`,
      });
    } catch (err) {
      console.error("Critical Multi-Table Mass Purge Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Failed to securely clean out relational architecture matrix.",
      });
    }
  },
);

router.post(
  "/audit-logs",
  verifyPermission("view_estate_logs", "logs_management"),
  async (req, res) => {
    try {
      const { id, startDate, endDate, limit = 50 } = req.body;
      console.log("fetching logs for:", id);

      // Fast fail if estate_id is completely missing
      if (!id) {
        return res
          .status(400)
          .json({ success: false, error: "user_id is required" });
      }

      let queryText = `
      SELECT * FROM app_logs 
      WHERE user_id = $1
    `;

      const queryParams = [id];

      // 2. Append optional calendar bounds securely
      if (startDate) {
        queryParams.push(`${startDate} 00:00:00`);
        queryText += ` AND created_at >= $${queryParams.length}`;
      }

      if (endDate) {
        queryParams.push(`${endDate} 23:59:59`);
        queryText += ` AND created_at <= $${queryParams.length}`;
      }

      // 3. Add order and capacity limits
      queryParams.push(Number(limit));
      queryText += ` ORDER BY created_at DESC LIMIT $${queryParams.length}`;

      // 4. Run raw execution on pool
      const { rows } = await pool.query(queryText, queryParams);

      res.json({
        success: true,
        data: rows,
      });
    } catch (error) {
      console.error("Audit logs fetch failed:", error);
      res.status(500).json({ success: false, error: "Internal Server Error" });
    }
  },
);

router.post(
  "/all-audit-logs",
  verifyPermission("view_estate_logs", "logs_management"),
  async (req, res) => {
    try {
      const { estate_id, role, startDate, endDate, limit = 50 } = req.body;
      console.log(`fetching logs for estate: ${estate_id} with role: ${role}`);

      // Fast fail if either required parameter is missing
      if (!estate_id) {
        return res
          .status(400)
          .json({ success: false, error: "estate_id is required" });
      }

      if (!role) {
        return res
          .status(400)
          .json({ success: false, error: "role is required" });
      }

      // 1. Core query baseline with both strict conditions built-in
      let queryText = `
      SELECT * FROM app_logs 
      WHERE estate_id = $1
        AND user_role = $2
    `;

      // Both values mapped to their strict placeholders ($1 and $2)
      const queryParams = [estate_id, role];

      // 2. Append optional calendar bounds securely
      if (startDate) {
        queryParams.push(`${startDate} 00:00:00`);
        queryText += ` AND created_at >= $${queryParams.length}`;
      }

      if (endDate) {
        queryParams.push(`${endDate} 23:59:59`);
        queryText += ` AND created_at <= $${queryParams.length}`;
      }

      // 3. Add order and capacity limits
      queryParams.push(Number(limit));
      queryText += ` ORDER BY created_at DESC LIMIT $${queryParams.length}`;

      // 4. Run raw execution on pool
      const { rows } = await pool.query(queryText, queryParams);

      res.json({
        success: true,
        data: rows,
      });
    } catch (error) {
      console.error("Audit logs fetch failed:", error);
      res.status(500).json({ success: false, error: "Internal Server Error" });
    }
  },
);

router.post(
  "/overall-audit-logs",
  verifyPermission("view_estate_logs", "logs_management"),
  async (req, res) => {
    try {
      const { startDate, endDate, limit = 50 } = req.body;
      console.log("fetching all logs overall");

      let queryText = `
      SELECT * FROM app_logs
      WHERE 1=1
    `;

      const queryParams = [];

      // 2. Append optional calendar bounds securely
      if (startDate) {
        queryParams.push(`${startDate} 00:00:00`);
        queryText += ` AND created_at >= $${queryParams.length}`;
      }

      if (endDate) {
        queryParams.push(`${endDate} 23:59:59`);
        queryText += ` AND created_at <= $${queryParams.length}`;
      }

      // 3. Add order and capacity limits
      queryParams.push(Number(limit));
      queryText += ` ORDER BY created_at DESC LIMIT $${queryParams.length}`;

      // 4. Run raw execution on pool
      const { rows } = await pool.query(queryText, queryParams);

      res.json({
        success: true,
        data: rows,
      });
    } catch (error) {
      console.error("Audit logs fetch failed:", error);
      res.status(500).json({ success: false, error: "Internal Server Error" });
    }
  },
);

router.post(
  "/section-audit-logs",
  verifyPermission("view_estate_logs", "logs_management"),
  async (req, res) => {
    try {
      const { estate_id, startDate, endDate, limit = 50 } = req.body;
      console.log(`fetching logs for estate: ${estate_id}`);

      // Fast fail if either required parameter is missing
      if (!estate_id) {
        return res
          .status(400)
          .json({ success: false, error: "estate_id is required" });
      }
      // 1. Core query baseline with both strict conditions built-in
      let queryText = `
      SELECT * FROM app_logs 
      WHERE estate_id = $1
    `;

      // Both values mapped to their strict placeholders ($1 and $2)
      const queryParams = [estate_id];

      // 2. Append optional calendar bounds securely
      if (startDate) {
        queryParams.push(`${startDate} 00:00:00`);
        queryText += ` AND created_at >= $${queryParams.length}`;
      }

      if (endDate) {
        queryParams.push(`${endDate} 23:59:59`);
        queryText += ` AND created_at <= $${queryParams.length}`;
      }

      // 3. Add order and capacity limits
      queryParams.push(Number(limit));
      queryText += ` ORDER BY created_at DESC LIMIT $${queryParams.length}`;

      // 4. Run raw execution on pool
      const { rows } = await pool.query(queryText, queryParams);

      res.json({
        success: true,
        data: rows,
      });
    } catch (error) {
      console.error("Audit logs fetch failed:", error);
      res.status(500).json({ success: false, error: "Internal Server Error" });
    }
  },
);

// ─── 🚀 SUPERADMIN TELEMETRY & ANALYTICS DASHBOARD CONTEXT ───
router.get("/dashboard-analytics", async (req, res, next) => {
  try {
    // 1. Gather counts from the super_admins master tables
    const adminMetricsQuery = `
        SELECT 
          COUNT(*)::int AS total_admins,
          COUNT(*) FILTER (WHERE sub_account = true)::int AS sub_accounts,
          COUNT(*) FILTER (WHERE sub_account = false)::int AS main_accounts,
          COALESCE(JSONB_AGG(permissions), '[]'::jsonb) AS permissions_matrix
        FROM super_admins;
      `;

    // 2. Fetch ecosystem structural counts and 30-minute rolling heartbeats
    const ecosystemQuery = `
        SELECT
          (SELECT COUNT(*)::int FROM estates) AS total_estates,
          (SELECT COUNT(*)::int FROM tenant_users) AS total_residents,
          (
            SELECT COUNT(*)::int 
            FROM tenant_users 
            WHERE last_activity_at >= NOW() - INTERVAL '30 minutes'
          ) AS residents_active_30m,
          (SELECT COUNT(*)::int FROM security_users) AS total_guards,
          (
            SELECT COUNT(*)::int 
            FROM security_users 
            WHERE last_activity_at >= NOW() - INTERVAL '30 minutes'
          ) AS guards_active_30m;
      `;

    // 3. Native inline extraction of current session matrices
    const liveSessionsQuery = `
        SELECT 
          s.sess,
          CASE 
            WHEN s.sess->>'ip' IS NOT NULL THEN
              EXISTS (
                SELECT 1 FROM security_ip_rules r 
                WHERE r.ip_or_cidr::text = s.sess->>'ip' AND r.rule_type = 'ALLOW'
              )
            ELSE FALSE
          END as is_whitelisted
        FROM "session" s
        JOIN super_admins a ON (
          s.sess->'passport'->'user'->>'id' IS NOT NULL 
          AND (s.sess->'passport'->'user'->>'id')::uuid = a.id
        )
        WHERE s.expire > CURRENT_TIMESTAMP;
      `;

    // 4. Fetch the absolute truth on permissions structure from your table
    const systemPermissionsQuery = `
        SELECT id, parent_permission FROM system_permissions;
      `;

    const estateQuery = `SELECT id, name FROM estates;`;
    const estateRes = await pool.query(estateQuery);

    // Execute all query matrices concurrently
    const [adminRes, ecosystemRes, sessionsRes, permissionsTableRes] =
      await Promise.all([
        pool.query(adminMetricsQuery),
        pool.query(ecosystemQuery),
        pool.query(liveSessionsQuery),
        pool.query(systemPermissionsQuery),
      ]);

    const adminMetrics = adminRes.rows[0];
    const ecosystemMetrics = ecosystemRes.rows[0];

    // 5. Compute Whitelisted vs Pending Connections from Active Sessions
    let liveConnectionsCount = 0;
    let pendingRequestsCount = 0;

    sessionsRes.rows.forEach((row) => {
      if (row.is_whitelisted) {
        liveConnectionsCount += 1;
      } else {
        pendingRequestsCount += 1;
      }
    });

    // 6. Build a structural dynamic parent-permission map from the DB records
    const dbPermissions = permissionsTableRes.rows;
    const permissionsMap = {};
    let totalAllocatedTokens = 0;

    // Extract all array instances assigned across admin profiles
    const rawPermissionsArray = adminMetrics.permissions_matrix || [];

    rawPermissionsArray.forEach((userPerms) => {
      if (!Array.isArray(userPerms)) return;

      userPerms.forEach((permId) => {
        // Find matching configuration node in database matrix
        const matchingRule = dbPermissions.find((p) => p.id === permId);
        if (!matchingRule) return;

        // Resolve target key: Use its parent rule or fallback to its own ID if it is a root node
        const targetParentKey =
          matchingRule.parent_permission || matchingRule.id;

        permissionsMap[targetParentKey] =
          (permissionsMap[targetParentKey] || 0) + 1;
        totalAllocatedTokens += 1;
      });
    });

    // 7. Return payload matching your frontend UI structural parameters
    return res.json({
      success: true,
      superAdminStats: {
        total: adminMetrics.total_admins || 0,
        subAccounts: adminMetrics.sub_accounts || 0,
        mainAccounts: adminMetrics.main_accounts || 0,
        liveAdmins: liveConnectionsCount,
        pendingRequests: pendingRequestsCount,
      },
      permissionDistribution: {
        chartMap: permissionsMap,
        totalAllocatedTokens: totalAllocatedTokens,
      },
      ecosystemStats: {
        totalEstates: ecosystemMetrics.total_estates || 0,
        totalResidents: ecosystemMetrics.total_residents || 0,
        activeResidents30m: ecosystemMetrics.residents_active_30m || 0,
        totalGuards: ecosystemMetrics.total_guards || 0,
        activeGuards30m: ecosystemMetrics.guards_active_30m || 0,
      },
      estatesList: estateRes.rows,
    });
  } catch (err) {
    console.error(
      "Superadmin Dashboard Analytical Compilation Core Error:",
      err,
    );
    return res.status(500).json({
      success: false,
      message: "Failed to compile multi-tenant operational data matrices.",
    });
  }
});

// POST /api/master/estates/notify
router.post(
  "/notify",
  verifyPermission("send_notifications", "notifications_management"),
  async (req, res) => {
    const { recipients, payload } = req.body;
    const { title, message, target } = payload || {};

    if (
      !Array.isArray(recipients) ||
      recipients.length === 0 ||
      !title ||
      !message ||
      !target
    ) {
      return res.status(400).json({
        success: false,
        message:
          "Payload missing required fields: recipients, title, message, target",
      });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      let notificationTargets = [];

      if (target === "admin") {
        // Recipients are estate IDs -> fetch root admins for each estate
        const rootAdminsQuery = await client.query(
          `SELECT e.id AS estate_id, e.name AS estate_name, eau.id AS root_admin_id 
           FROM estates e
           JOIN estate_admin_users eau ON LOWER(e.root_admin_email) = LOWER(eau.email)
           WHERE e.id = ANY($1::uuid[])`,
          [recipients],
        );

        if (rootAdminsQuery.rows.length === 0) {
          await client.query("ROLLBACK");
          return res.status(404).json({
            success: false,
            message: "No root admin records found for the selected estates.",
          });
        }

        notificationTargets = rootAdminsQuery.rows.map((row) => ({
          estateId: row.estate_id,
          userId: row.root_admin_id,
          estateName: row.estate_name,
        }));
      } else {
        const usersQuery = await client.query(
          `SELECT id AS user_id, estate_id FROM users WHERE id = ANY($1::uuid[])`,
          [recipients],
        );

        notificationTargets = usersQuery.rows.map((row) => ({
          estateId: row.estate_id,
          userId: row.user_id,
        }));
      }

      for (const t of notificationTargets) {
        const notificationRes = await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, $3, $4, $5, 'emergency') RETURNING *`,
          [t.estateId, t.userId, target, title, message],
        );

        const insertedRecord = notificationRes.rows[0];

        // Emit via Socket.IO to respective rooms
        if (target === "admin") {
          io.to(`admins_estate_${t.estateId}`).emit(
            "new_notification",
            insertedRecord,
          );
        } else {
          io.to(`user_${t.userId}`).emit("new_notification", insertedRecord);
        }
      }

      // Audit Log Footprint
      await createAuditLog(req, {
        action_type: "BULK_NOTIFY",
        target_resource: target === "admin" ? "estates" : "users",
        description: `Dispatched system alert [${title}] to ${notificationTargets.length} ${target}(s).`,
        state_after: {
          title,
          message,
          recipient_count: notificationTargets.length,
          target,
        },
        log_type: "notification",
      });

      await client.query("COMMIT");
      return res.json({
        success: true,
        message: `Notification successfully dispatched to ${notificationTargets.length} ${target}(s).`,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Bulk Notification Dispatch Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal transaction failure sending notifications.",
      });
    } finally {
      client.release();
    }
  },
);

// POST /api/master/estates/notify-all
// Broadcast system alerts globally ONLY to root admins of all active estates
// router.post(
//   "/notify-all",
//   verifyPermission("send_notifications", "notifications_management"),
//   async (req, res) => {
//     const { title, message } = req.body;

//     if (!title || !message) {
//       return res.status(400).json({
//         success: false,
//         message: "Payload missing required fields: title, message",
//       });
//     }

//     const client = await pool.connect();
//     try {
//       await client.query("BEGIN");

//       // Query root admins across all active estates
//       const rootAdminsRes = await client.query(
//         `SELECT e.id AS estate_id, eau.id AS root_admin_id 
//          FROM estates e
//          JOIN estate_admin_users eau ON LOWER(e.root_admin_email) = LOWER(eau.email)
//          WHERE e.status = 'ACTIVE'`,
//       );

//       let totalDispatched = 0;

//       for (const row of rootAdminsRes.rows) {
//         const notif = await client.query(
//           `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
//            VALUES ($1, $2, 'admin', $3, $4, 'emergency') RETURNING *`,
//           [row.estate_id, row.root_admin_id, title, message],
//         );

//         const adminRoom = `admins_estate_${row.estate_id}`;
//         io.to(adminRoom).emit("new_notification", notif.rows[0]);
//         totalDispatched++;
//       }

//       // System-wide Forensic Audit Log
//       await createAuditLog(req, {
//         action_type: "BROADCAST_ALL_ESTATES",
//         target_resource: "estates",
//         target_id: "ALL",
//         description: `Broadcasted platform alert [${title}] to root admins across ${totalDispatched} active estates.`,
//         state_after: { title, message, totalDispatched },
//         log_type: "notification",
//       });

//       await client.query("COMMIT");
//       return res.json({
//         success: true,
//         message: `Global broadcast dispatched to root admins across ${totalDispatched} active estates.`,
//       });
//     } catch (err) {
//       await client.query("ROLLBACK");
//       console.error("Global Broadcast Root Admin Failure:", err);
//       return res.status(500).json({
//         success: false,
//         message: "Internal transaction failure executing broadcast.",
//       });
//     } finally {
//       client.release();
//     }
//   },
// );

const checkSubscriptionExpirations = async () => {
  console.log("Checking Subscription Expirations...");
  const client = await pool.connect();

  try {
    const subscriptionQuery = `
      SELECT 
        e.id AS estate_id, 
        e.name AS estate_name, 
        e.plan, 
        e.subscription_expiry,
        
        -- Categorize state into 'EXPIRED' or 'EXPIRING_SOON'
        CASE 
          WHEN e.subscription_expiry < NOW() THEN 'EXPIRED'
          WHEN e.subscription_expiry <= (NOW() + INTERVAL '7 days') THEN 'EXPIRING_SOON'
        END AS expiry_status,

        -- Calculate remaining days cleanly
        CEIL(EXTRACT(EPOCH FROM (e.subscription_expiry - NOW())) / 86400)::int AS days_remaining

      FROM estates e
      WHERE e.subscription_expiry IS NOT NULL
        AND (
          e.subscription_expiry < NOW() 
          OR e.subscription_expiry <= (NOW() + INTERVAL '7 days')
        );
    `;

    const { rows: expiringEstates } = await client.query(subscriptionQuery);
    if (expiringEstates.length === 0) return;

    for (const record of expiringEstates) {
      let alertTitle = "";
      let alertMessage = "";
      let notifType = "general";

      if (record.expiry_status === "EXPIRED") {
        alertTitle = "Subscription Expired 🔴";
        alertMessage = `Estate "${record.estate_name}" (${record.plan} Plan) subscription expired on ${new Date(record.subscription_expiry).toLocaleDateString()}.`;
        notifType = "emergency";
      } else if (record.expiry_status === "EXPIRING_SOON") {
        alertTitle = "Subscription Expiring Soon ⚠️";
        const daysLabel =
          record.days_remaining <= 1
            ? "1 day"
            : `${record.days_remaining} days`;
        alertMessage = `Estate "${record.estate_name}" (${record.plan} Plan) subscription will expire in ${daysLabel} (${new Date(record.subscription_expiry).toLocaleDateString()}).`;
        notifType = "warning";
      }

      // Check if a notification for this exact event was already created today to avoid spamming
      const duplicateCheck = await client.query(
        `SELECT id FROM notifications 
         WHERE estate_id = $1 
           AND recipient_role = 'super_admin' 
           AND title = $2 
           AND created_at >= CURRENT_DATE`,
        [record.estate_id, alertTitle],
      );

      if (duplicateCheck.rows.length === 0) {
        // Insert notification for Super Admins
        const notifResult = await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, NULL, 'super_admin', $2, $3, $4)
           RETURNING *`,
          [record.estate_id, alertTitle, alertMessage, notifType],
        );

        // Emit real-time update to Super Admins room
        io.to("superadmins").emit("new_notification", notifResult.rows[0]);
      }
    }
  } catch (err) {
    console.error("Subscription Expiration Check Error:", err);
  } finally {
    client.release();
  }
};

export { checkSubscriptionExpirations };

export default router;
