import express from "express";
import pool from "./db.js";
import {
  isAuth,
  ensureAdmin,
  authorizeEstate,
  verifyPermission,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import { createAppAuditLog } from "./helpers.js";

const router = express.Router();

router.use(isAuth);

// ==========================================
// A. SERVICES DIRECTORY ENDPOINTS
// ==========================================

// 1. FETCH ALL SERVICES WITH THEIR RELATIONAL VENDORS LIST
router.get(
  "/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  verifyPermission("view_services_catalog", "services_management"),
  async (req, res) => {
    try {
      const queryText = `
      SELECT es.id, es.estate_id, es.service_name, es.is_available, es.created_at,
             COALESCE(
               json_agg(
                 json_build_object('id', ev.id, 'name', ev.name, 'email', ev.email, 'phone', ev.phone)
               ) FILTER (WHERE ev.id IS NOT NULL), '[]'::json
             ) as vendors
      FROM estate_services es
      LEFT JOIN estate_vendors ev ON ev.id = ANY(es.vendors)
      WHERE es.estate_id = $1
      GROUP BY es.id
      ORDER BY es.service_name ASC
    `;
      const result = await pool.query(queryText, [req.params.estate_id]);
      res.json({ success: true, services: result.rows });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

router.post(
  "/tenant/all",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  async (req, res) => {
    const estateId = req.body.estate_id;
    try {
      const queryText = `
      SELECT es.id, es.estate_id, es.service_name, es.is_available, es.created_at,
             COALESCE(
               json_agg(
                 json_build_object('id', ev.id, 'name', ev.name, 'email', ev.email, 'phone', ev.phone)
               ) FILTER (WHERE ev.id IS NOT NULL), '[]'::json
             ) as vendors
      FROM estate_services es
      LEFT JOIN estate_vendors ev ON ev.id = ANY(es.vendors)
      WHERE es.estate_id = $1
      GROUP BY es.id
      ORDER BY es.service_name ASC
    `;
      const result = await pool.query(queryText, [estateId]);
      res.json({ success: true, services: result.rows });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// 2. CREATE SERVICE CATEGORY WITH MULTIPLE RELATIONAL VENDORS
router.post(
  "/",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  verifyPermission("manage_services_catalog", "services_management"),
  async (req, res) => {
    const { service_name, vendors, estate_id } = req.body;

    console.log("Service body:", req.body);
    if (!service_name || !Array.isArray(vendors)) {
      return res
        .status(400)
        .json({ error: "Service name and a valid vendors list are required." });
    }

    const client = await pool.connect();
    try {
      await client.query("BEGIN");

      // Step A: Insert the base service category
      const serviceResult = await client.query(
        `INSERT INTO estate_services (estate_id, service_name, vendors, is_available)
       VALUES ($1, $2, '{}'::uuid[], true) RETURNING *`,
        [estate_id, service_name],
      );
      const newServiceId = serviceResult.rows[0].id;

      const vendorIds = [];

      // Step B: Loop through and insert each vendor
      for (const vendor of vendors) {
        const vendorResult = await client.query(
          `INSERT INTO estate_vendors (estate_id, service_id, name, email, phone)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [
            estate_id,
            newServiceId,
            vendor.name,
            vendor.email || null,
            vendor.phone || null,
          ],
        );
        vendorIds.push(vendorResult.rows[0].id);
      }

      // Step C: Update the service row with generated vendor UUIDs
      const updatedServiceResult = await client.query(
        `UPDATE estate_services SET vendors = $1 WHERE id = $2 RETURNING *`,
        [vendorIds, newServiceId],
      );

      await client.query("COMMIT");

      const createdService = updatedServiceResult.rows[0];

      // 1. Respond to admin client instantly
      res.status(201).json({
        success: true,
        service: { ...createdService, vendors },
      });

      // 2. Track service entry footprint asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "ESTATE_SERVICE_CREATED",
        target_resource: "estate_services",
        target_id: newServiceId,
        description: `Admin registered new service category "${service_name}" with a roster of ${vendors.length} vendor(s).`,
        state_before: null,
        state_after: { ...createdService, embedded_vendors: vendors },
        urgency: "MEDIUM",
      }).catch((err) => console.error("Audit log error:", err));
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      res.status(500).json({ error: err.message });
    } finally {
      client.release();
    }
  },
);

// -------------------- EDIT SERVICE CATEGORY (LOGGED) --------------------
router.put(
  "/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  verifyPermission("manage_services_catalog", "services_management"),
  async (req, res) => {
    const { id } = req.params;
    const {
      service_name,
      vendors,
      is_available,
      estate_id: estateId,
    } = req.body;

    if (!Array.isArray(vendors)) {
      return res
        .status(400)
        .json({ error: "Vendors dataset must be an array representation." });
    }

    const client = await pool.connect();
    try {
      // 🧠 Fetch snapshot BEFORE modification to preserve historical logs
      const serviceCheck = await client.query(
        "SELECT * FROM estate_services WHERE id = $1 AND estate_id = $2",
        [id, estateId],
      );

      if (serviceCheck.rows.length === 0) {
        client.release();
        return res.status(404).json({ error: "Service record not found." });
      }

      // Fetch matching child vendors to build complete pre-state snapshot context
      const vendorsCheck = await client.query(
        "SELECT id, name, email, phone FROM estate_vendors WHERE service_id = $1 AND estate_id = $2",
        [id, estateId],
      );

      const stateBefore = {
        ...serviceCheck.rows[0],
        historical_vendors: vendorsCheck.rows,
      };

      await client.query("BEGIN");

      // Step A: Wipe out old vendor bindings
      await client.query(
        "DELETE FROM estate_vendors WHERE service_id = $1 AND estate_id = $2",
        [id, estateId],
      );

      const vendorIds = [];

      // Step B: Insert the updated rosters list
      for (const vendor of vendors) {
        const vendorResult = await client.query(
          `INSERT INTO estate_vendors (estate_id, service_id, name, email, phone)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
          [
            estateId,
            id,
            vendor.name,
            vendor.email || null,
            vendor.phone || null,
          ],
        );
        vendorIds.push(vendorResult.rows[0].id);
      }

      // Step C: Push changes down to the parent entry
      const result = await client.query(
        `UPDATE estate_services 
       SET service_name = $1, vendors = $2, is_available = $3
       WHERE id = $4 AND estate_id = $5 RETURNING *`,
        [service_name, vendorIds, is_available, id, estateId],
      );

      await client.query("COMMIT");

      const updatedService = result.rows[0];

      // 1. Respond to admin client instantly
      res.json({ success: true, service: { ...updatedService, vendors } });

      // 2. Track mutation footprint asynchronously
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "ESTATE_SERVICE_MODIFIED",
        target_resource: "estate_services",
        target_id: id,
        description: `Admin updated configurations for service category "${service_name}". Roster updated to ${vendors.length} vendors.`,
        state_before: stateBefore,
        state_after: { ...updatedService, embedded_vendors: vendors },
        urgency: "MEDIUM",
      }).catch((err) => console.error("Audit log error:", err));
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      res.status(500).json({ error: err.message });
    } finally {
      client.release();
    }
  },
);

// 2. PATCH DISPATCH WORK ORDERS AND UPDATE VENDORS ARRAY
router.patch(
  "/requests/:id/status",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  async (req, res) => {
    const { id } = req.params;
    const { is_dispatched, dispatched_vendors, estate_id: estateId } = req.body;

    try {
      const preCheck = await pool.query(
        "SELECT * FROM service_requests WHERE id = $1 AND estate_id = $2",
        [id, estateId],
      );

      if (preCheck.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Service request ticket not found." });
      }

      const requestStateBefore = preCheck.rows[0];

      const result = await pool.query(
        `UPDATE service_requests 
       SET is_dispatched = COALESCE($1, is_dispatched),
           dispatched_vendors = COALESCE($2, dispatched_vendors)
       WHERE id = $3 AND estate_id = $4 RETURNING *`,
        [is_dispatched, dispatched_vendors, id, estateId],
      );

      const updatedRequest = result.rows[0];

      // 1. Respond to admin client instantly
      res.json({ success: true, request: updatedRequest });

      // 2. Log work dispatch adjustments asynchronously
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "MAINTENANCE_REQUEST_DISPATCHED",
        target_resource: "service_requests",
        target_id: id,
        description: `Admin modified dispatch properties for request. Status marked dispatched: ${updatedRequest.is_dispatched}.`,
        state_before: requestStateBefore,
        state_after: updatedRequest,
        urgency: "MEDIUM",
      });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// -------------------- DELETE SERVICE CATEGORY (LOGGED) --------------------
router.delete(
  "/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  verifyPermission("manage_services_catalog", "services_management"),
  async (req, res) => {
    const { id } = req.params;
    const estateId = req.query.estate_id;
    const client = await pool.connect();
    try {
      // 🧠 Fetch the core service and child vendor roster states BEFORE wiping them out
      const serviceCheck = await client.query(
        "SELECT * FROM estate_services WHERE id = $1 AND estate_id = $2",
        [id, estateId],
      );

      if (serviceCheck.rows.length === 0) {
        client.release();
        return res
          .status(404)
          .json({ error: "Service record erasure target missing." });
      }

      const vendorsCheck = await client.query(
        "SELECT id, name, email, phone FROM estate_vendors WHERE service_id = $1 AND estate_id = $2",
        [id, estateId],
      );

      const fullStateBefore = {
        ...serviceCheck.rows[0],
        purged_vendors: vendorsCheck.rows,
      };

      await client.query("BEGIN");

      // Clean up dependent child vendor accounts first
      await client.query(
        "DELETE FROM estate_vendors WHERE service_id = $1 AND estate_id = $2",
        [id, estateId],
      );

      // Delete service category entry
      await client.query(
        "DELETE FROM estate_services WHERE id = $1 AND estate_id = $2",
        [id, estateId],
      );

      await client.query("COMMIT");

      // 1. Respond to admin client instantly
      res.json({
        success: true,
        message: "Service and associated vendor profiles removed successfully.",
      });

      // 2. Track destructive purge asynchronously
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "ESTATE_SERVICE_DELETED",
        target_resource: "estate_services",
        target_id: id,
        description: `Admin permanently dropped service entry "${fullStateBefore.service_name}" along with its roster of ${vendorsCheck.rows.length} vendors.`,
        state_before: fullStateBefore,
        state_after: null,
        urgency: "MEDIUM",
      }).catch((err) => console.error("Audit log error:", err));
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      res.status(500).json({ error: err.message });
    } finally {
      client.release();
    }
  },
);

// ==========================================
// B. RESIDENT REQUESTS OPERATIONS ENDPOINTS
// ==========================================

// 1. FETCH ALL REQUESTS WITH NESTED COMPATIBLE VENDOR OPTIONS
router.get(
  "/requests/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  verifyPermission("view_service_requests", "services_management"),
  async (req, res) => {
    try {
      const queryText = `
      SELECT sr.*, es.service_name,
             COALESCE(
               (SELECT json_agg(json_build_object('id', ev.id, 'name', ev.name, 'phone', ev.phone, 'email', ev.email))
                FROM estate_vendors ev
                WHERE ev.service_id = sr.service_id AND ev.estate_id = $1), '[]'::json
             ) as available_vendors
      FROM service_requests sr
      LEFT JOIN estate_services es ON sr.service_id = es.id
      WHERE sr.estate_id = $1 
      ORDER BY sr.requested_at DESC
    `;
      const result = await pool.query(queryText, [req.params.estate_id]);
      res.json({ success: true, requests: result.rows });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  },
);

// -------------------- CREATE MAINTENANCE REQUEST (LOGGED) --------------------
router.post(
  "/requests",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  async (req, res) => {
    const { estate_id, service_id, time_preferred, unit, description } =
      req.body;

    if (!estate_id || !service_id || !description?.trim()) {
      return res.status(400).json({
        success: false,
        message: "Required booking payload properties are missing.",
      });
    }

    try {
      const residentId = req.user.id;
      const residentName = req.user.name || "Resident";
      const residentUnit = unit || "N/A";

      const queryText = `
        INSERT INTO service_requests (
          estate_id, service_id, resident_id, resident_name, 
          resident_unit, time_preferred, description, is_dispatched, is_completed
        )
        VALUES ($1, $2, $3, $4, $5, $6, $7, false, false) 
        RETURNING *
      `;

      const result = await pool.query(queryText, [
        estate_id,
        service_id,
        residentId,
        residentName,
        residentUnit,
        time_preferred || "Morning (9AM - 12PM)",
        description.trim(),
      ]);

      const targetRequest = result.rows[0];

      // 1. Run audit log safely first (or in a non-blocking catch)
      try {
        await createAppAuditLog(req, {
          estate_id: estate_id,
          action_type: "MAINTENANCE_REQUEST_CREATED",
          target_resource: "service_requests",
          target_id: targetRequest.id,
          description: `Resident "${residentName}" submitted a new maintenance issue work order for unit "${residentUnit}".`,
          state_before: null,
          state_after: targetRequest,
          urgency: "MEDIUM",
        });
      } catch (auditErr) {
        console.error("Audit log creation failed:", auditErr.message);
      }

      // 2. Return HTTP response ONCE at the very end
      return res.status(201).json({ success: true, request: targetRequest });
    } catch (err) {
      console.error("Service request error:", err.message);

      // Prevent double header errors by checking if headers were already sent
      if (!res.headersSent) {
        return res.status(500).json({ success: false, error: err.message });
      }
    }
  },
);
// 5. FETCH HISTORY FOR TENANT WITH ESTATE_ID SENT IN POST BODY
router.post(
  "/requests/tenant/history",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  async (req, res) => {
    const { estate_id } = req.body;

    if (!estate_id) {
      return res.status(400).json({
        success: false,
        message: "Estate context identification token is required.",
      });
    }

    try {
      const queryText = `
      SELECT sr.*, es.service_name,
             COALESCE(
               (SELECT json_agg(json_build_object('name', ev.name, 'phone', ev.phone, 'email', ev.email))
                FROM estate_vendors ev
                WHERE ev.id = ANY(sr.dispatched_vendors)), '[]'::json
             ) as assigned_vendors
      FROM service_requests sr
      LEFT JOIN estate_services es ON sr.service_id = es.id
      WHERE sr.estate_id = $1 AND sr.resident_id = $2
      ORDER BY sr.requested_at DESC
    `;

      const result = await pool.query(queryText, [estate_id, req.user.id]);
      res.json({ success: true, requests: result.rows });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },
);

// RESIDENT COMPLETION TOGGLE API
router.patch(
  "/requests/tenant/:id/complete",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  async (req, res) => {
    const { id } = req.params;
    const { is_completed } = req.body;
    const estate_id = req.body.estate_id;

    try {
      // 🧠 Grab operational state before execution for tracking purposes
      const preCheck = await pool.query(
        `SELECT * FROM service_requests WHERE id = $1 AND resident_id = $2 AND estate_id = $3`,
        [id, req.user.id, estate_id],
      );

      if (preCheck.rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "Request item record trace not found.",
        });
      }

      const stateBefore = preCheck.rows[0];

      const result = await pool.query(
        `UPDATE service_requests 
       SET is_completed = $1
       WHERE id = $2 AND resident_id = $3 AND estate_id = $4
       RETURNING *`,
        [is_completed, id, req.user.id, estate_id],
      );

      const updatedRequest = result.rows[0];

      // 1. Respond to resident client instantly
      res.json({ success: true, request: updatedRequest });

      // 2. Track work verification state asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "MAINTENANCE_REQUEST_COMPLETION_TOGGLED",
        target_resource: "service_requests",
        target_id: id,
        description: `Resident marked maintenance ticket ID ${id} as ${updatedRequest.is_completed ? "COMPLETED" : "INCOMPLETE"}.`,
        state_before: stateBefore,
        state_after: updatedRequest,
        urgency: "MEDIUM",
      });
    } catch (err) {
      res.status(500).json({ success: false, error: err.message });
    }
  },
);

// -------------------- DELETE SERVICE REQUEST (LOGGED) --------------------
router.delete(
  "/requests/:id",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("services_dispatch"),
  async (req, res) => {
    const { id } = req.params;
    const estateId = req.query.estate_id;
    console.log("Delete service api hit:", id, estateId);

    try {
      const result = await pool.query(
        `DELETE FROM service_requests 
         WHERE id = $1 AND estate_id = $2 AND is_dispatched = false 
         RETURNING *`,
        [id, estateId],
      );

      if (result.rowCount === 0) {
        return res.status(400).json({
          success: false,
          message:
            "Request not found or cannot be deleted because it is already dispatched.",
        });
      }

      const purgedRequestData = result.rows[0];

      // 1. Await Audit Log BEFORE sending res.json so any error hits catch block BEFORE headers are sent
      try {
        await createAppAuditLog(req, {
          estate_id: estateId,
          action_type: "MAINTENANCE_REQUEST_DELETED",
          target_resource: "service_requests",
          target_id: id,
          description: `Deleted undispatched maintenance work ticket ID ${id}.`,
          state_before: purgedRequestData,
          state_after: null,
          urgency: "MEDIUM",
        });
      } catch (auditErr) {
        // Log the audit failure without failing the entire request if you want non-blocking logs
        console.error("Failed to create audit log entry:", auditErr.message);
      }

      // 2. Respond to admin client LAST
      return res.json({
        success: true,
        message: "Service request removed successfully.",
      });
    } catch (err) {
      console.error("Delete request error:", err);

      // Safety guard: only send 500 if headers haven't gone out
      if (!res.headersSent) {
        return res.status(500).json({ error: err.message });
      }
    }
  },
);

export default router;
