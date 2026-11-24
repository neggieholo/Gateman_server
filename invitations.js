import express from "express";
import pool from "./db.js";
import {
  authorizeEstate,
  ensureAdmin,
  isAuth,
  verifyPermission,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import crypto from "crypto";
import cron from "node-cron";
import { io } from "./server.js";
import { createAppAuditLog, verifyGuardActiveShift } from "./helpers.js";

const router = express.Router();

router.use(isAuth);

export const sendPushNotification = async (token, title, body, data = {}) => {
  try {
    const message = {
      to: token,
      sound: "default",
      title: title,
      body: body,
      data: data,
      priority: "high",
      channelId: "default",
    };

    const response = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message),
    });

    const resData = await response.json();
    return resData;
  } catch (err) {
    console.error("Push Notification Error:", err);
  }
};

export const sendEmergencyCall = async (token, channelName, callerName) => {
  try {
    const message = {
      to: token,
      priority: "high",
      android: {
        priority: "high",
        fullScreenIntent: true,
      },
      data: {
        type: "EMERGENCY_CALL",
        channelName: channelName,
        callerName: callerName,
        isVoIP: true,
      },
    };

    const response = await fetch("https://exp.host/--/api/v2/push/send", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(message),
    });

    const resData = await response.json();
    return resData;
  } catch (err) {
    console.error("Push Notification Error:", err);
  }
};

// --- 1. GET ALL INVITATIONS ---
router.get(
  "/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("view_checkins", "visitor_operations"),
  async (req, res) => {
    const estate_id = req.params.estate_id;

    try {
      const query = `
      SELECT 
        i.*, 
        u.name as resident_name, 
        u.locations,
        e.name AS estate_name,
        e.address AS estate_address,
        e.lga,
        e.town
      FROM invitations i
      LEFT JOIN tenant_users u ON i.resident_id = u.id
      LEFT JOIN estates e ON i.estate_id = e.id
      WHERE i.estate_id = $1        
      ORDER BY 
        CASE WHEN i.status = 'checked_in' THEN 1 ELSE 2 END, 
        i.actual_checkin_date DESC;
    `;

      const { rows } = await pool.query(query, [estate_id]);
      res.json(rows);
    } catch (err) {
      console.error("Invitations Fetch Error:", err);
      res.status(500).json({ error: "Failed to fetch invitations" });
    }
  },
);

// --- 1. GET ALL INVITATIONS (FOR TRACK GUEST VIEW) ---
router.get(
  "/resident/get-all",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const { estate_id } = req.query;
    const user_id = req.user.id;

    try {
      const query = `
      SELECT * FROM invitations 
      WHERE estate_id = $1 AND resident_id = $2
      ORDER BY created_at DESC;
    `;
      const { rows } = await pool.query(query, [estate_id, user_id]);
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to fetch invitations" });
    }
  },
);

// --- 2. CREATE AN INVITATION (WITH SECURE CODE & EXCLUSIONS) ---
router.post(
  "/",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const {
      guest_name,
      guest_phone,
      guest_image_url,
      invite_type,
      start_date,
      end_date,
      start_time,
      end_time,
      excluded_dates,
      estate_id,
      staff_position,
      permitted_days,
    } = req.body;

    const resident_id = req.user.id;
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      let accessCode;
      let isUnique = false;
      while (!isUnique) {
        accessCode = crypto.randomInt(100000, 999999).toString();
        const check = await client.query(
          "SELECT 1 FROM invitations WHERE access_code = $1 AND estate_id = $2 AND is_used = false",
          [accessCode, estate_id],
        );
        if (check.rows.length === 0) isUnique = true;
      }

      const finalExclusions = Array.isArray(excluded_dates)
        ? JSON.stringify(excluded_dates)
        : JSON.stringify([]);
      const finalPermittedDays = Array.isArray(permitted_days)
        ? JSON.stringify(permitted_days)
        : JSON.stringify([]);

      const insertQuery = `
      INSERT INTO invitations (
        estate_id, resident_id, guest_name, guest_phone, guest_image_url, 
        access_code, invite_type, start_date, end_date, 
        start_time, end_time, excluded_dates, staff_position,
        permitted_days
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14) 
      RETURNING *;
    `;

      const { rows } = await client.query(insertQuery, [
        estate_id,
        resident_id,
        guest_name,
        guest_phone || null,
        guest_image_url || null,
        accessCode,
        invite_type,
        start_date,
        end_date,
        start_time,
        end_time,
        finalExclusions,
        staff_position || null,
        finalPermittedDays,
      ]);

      await client.query("COMMIT");

      const newInvitation = rows[0];

      // 1. Respond instantly to resident
      res.status(201).json(newInvitation);

      // 2. Log gate token authorization asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "VISITOR_PASS_GENERATED",
        target_resource: "invitations",
        target_id: newInvitation.id,
        description: `Resident generated a secure ${invite_type} pass for visitor "${guest_name}" (Code: ${accessCode}).`,
        state_before: null,
        state_after: newInvitation,
        urgency: "HIGH",
      });
    } catch (err) {
      if (client) await client.query("ROLLBACK").catch(() => {});
      console.error("Invitation Error:", err);
      res.status(500).json({ error: "Failed to generate invitation" });
    } finally {
      client.release();
    }
  },
);

// --- 4. LOG ACTIVITY (CHECK-IN / CHECK-OUT) ---
router.post(
  "/log-activity/:id",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyGuardActiveShift,
  async (req, res) => {
    const { id } = req.params;
    const { action, estate_id } = req.body;
    const guardName =
      req.user.role === "ADMIN" ? "ADMIN" : `Security guard ${req.user.name}`;

    const now = new Date();
    const currentDate = now.toISOString().split("T")[0];
    const currentTime = now.toTimeString().split(" ")[0].substring(0, 5);

    try {
      // 1. Fetch current invitation state (state_before)
      const inviteResult = await pool.query(
        "SELECT * FROM invitations WHERE id = $1 AND estate_id = $2",
        [id, estate_id],
      );

      if (inviteResult.rows.length === 0) {
        return res.status(404).json({ error: "Invitation not found" });
      }

      const invite = inviteResult.rows[0];

      // 2. Validation Guardrails
      if (invite.is_cancelled)
        return res.status(400).json({ error: "Invitation is cancelled" });

      // Check Exclusions for Multi-Entry
      if (
        invite.invite_type === "multi_entry" &&
        invite.excluded_dates?.includes(currentDate)
      ) {
        return res
          .status(403)
          .json({ error: "Access denied: Date is excluded" });
      }

      let updateQuery;
      let params;

      if (action === "check_in") {
        updateQuery = `
        UPDATE invitations 
        SET 
          status = 'checked_in',
          actual_checkin_date = $1,
          actual_checkin_time = $2,
          actual_checkout_date = NULL,
          actual_checkout_time = NULL,
          is_used = TRUE
        WHERE id = $3
        RETURNING *;
      `;
        params = [currentDate, currentTime, id];
      } else if (action === "check_out") {
        updateQuery = `
        UPDATE invitations 
        SET 
          status = 'checked_out',
          actual_checkout_date = $1,
          actual_checkout_time = $2
        WHERE id = $3
        RETURNING *;
      `;
        params = [currentDate, currentTime, id];
      }

      const { rows } = await pool.query(updateQuery, params);
      const updatedInvitation = rows[0]; // state_after

      const tokenResult = await pool.query(
        "SELECT push_token FROM tenant_users WHERE id = $1",
        [invite.resident_id],
      );

      const pushToken = tokenResult.rows[0]?.push_token;

      const notificationTitle =
        action === "check_in" ? "Guest Checked In ✅" : "Guest Checked Out ✅";
      const notificationBody =
        action === "check_in"
          ? `${invite.guest_name} has checked in.`
          : `${invite.guest_name} has checked out.`;

      // Fix context referencing variables safely
      const inviteData = {
        type: "notification",
        subtype: "visitor_activity",
        user_id: invite.resident_id,
        message: notificationBody,
      };

      if (pushToken) {
        sendPushNotification(
          pushToken,
          notificationTitle,
          notificationBody,
          inviteData,
        );
      }

      // 3. Respond instantly to terminal client
      res.json({
        message: `Guest ${action.replace("_", " ")} successfully`,
        invitation: updatedInvitation,
      });

      // 4. Clean asynchronous call using your createAppAuditLog helper function
      const actionType =
        action === "check_in" ? "GUEST_CHECKED_IN" : "GUEST_CHECKED_OUT";
      const actionDisplay =
        action === "check_in" ? "checked in" : "checked out";

      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: actionType,
        target_resource: "invitations",
        target_id: id,
        description: `${guardName} processed ${actionDisplay} for visitor "${invite.guest_name}" (Access Code: ${invite.access_code}).`,
        state_before: invite,
        state_after: updatedInvitation,
        urgency: "INFO",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to log activity" });
    }
  },
);

router.post(
  "/admin/log-activity/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("override_entry_code", "visitor_operations"),
  async (req, res) => {
    console.log("Log Activity Request Params:", req.params);
    const { id } = req.params;
    const { action } = req.body;
    const estate_id = req.query.estate_id;
    const guardName =
      req.user.role === "ADMIN" ? "ADMIN" : `Security guard ${req.user.name}`;

    const now = new Date();
    const currentDate = now.toISOString().split("T")[0];
    const currentTime = now.toTimeString().split(" ")[0].substring(0, 5);

    try {
      // 1. Fetch current invitation state (state_before)
      const inviteResult = await pool.query(
        "SELECT * FROM invitations WHERE id = $1 AND estate_id = $2",
        [id, estate_id],
      );

      if (inviteResult.rows.length === 0) {
        return res.status(404).json({ error: "Invitation not found" });
      }

      const invite = inviteResult.rows[0];

      // 2. Validation Guardrails
      if (invite.is_cancelled)
        return res.status(400).json({ error: "Invitation is cancelled" });

      // Check Exclusions for Multi-Entry
      if (
        invite.invite_type === "multi_entry" &&
        invite.excluded_dates?.includes(currentDate)
      ) {
        return res
          .status(403)
          .json({ error: "Access denied: Date is excluded" });
      }

      let updateQuery;
      let params;

      if (action === "check_in") {
        updateQuery = `
        UPDATE invitations 
        SET 
          status = 'checked_in',
          actual_checkin_date = $1,
          actual_checkin_time = $2,
          actual_checkout_date = NULL,
          actual_checkout_time = NULL,
          is_used = TRUE
        WHERE id = $3
        RETURNING *;
      `;
        params = [currentDate, currentTime, id];
      } else if (action === "check_out") {
        updateQuery = `
        UPDATE invitations 
        SET 
          status = 'checked_out',
          actual_checkout_date = $1,
          actual_checkout_time = $2
        WHERE id = $3
        RETURNING *;
      `;
        params = [currentDate, currentTime, id];
      }

      const { rows } = await pool.query(updateQuery, params);
      const updatedInvitation = rows[0]; // state_after

      const tokenResult = await pool.query(
        "SELECT push_token FROM tenant_users WHERE id = $1",
        [invite.resident_id],
      );

      const pushToken = tokenResult.rows[0]?.push_token;

      const notificationTitle =
        action === "check_in" ? "Guest Checked In ✅" : "Guest Checked Out ✅";
      const notificationBody =
        action === "check_in"
          ? `${invite.guest_name} has checked in.`
          : `${invite.guest_name} has checked out.`;

      // Fix context referencing variables safely
      const inviteData = {
        type: "notification",
        subtype: "visitor_activity",
        user_id: invite.resident_id,
        message: notificationBody,
      };

      if (pushToken) {
        sendPushNotification(
          pushToken,
          notificationTitle,
          notificationBody,
          inviteData,
        );
      }

      // 3. Respond instantly to terminal client
      res.json({
        message: `Guest ${action.replace("_", " ")} successfully`,
        invitation: updatedInvitation,
      });

      // 4. Clean asynchronous call using your createAppAuditLog helper function
      const actionType =
        action === "check_in" ? "GUEST_CHECKED_IN" : "GUEST_CHECKED_OUT";
      const actionDisplay =
        action === "check_in" ? "checked in" : "checked out";

      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: actionType,
        target_resource: "invitations",
        target_id: id,
        description: `${guardName} processed ${actionDisplay} for visitor "${invite.guest_name}" (Access Code: ${invite.access_code}).`,
        state_before: invite,
        state_after: updatedInvitation,
        urgency: "INFO",
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to log activity" });
    }
  },
);
// --- 4. CANCEL INVITATION---
router.delete(
  "/:id",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const { id } = req.params;
    const user_id = req.user.id;
    const estateId = req.query.estate_id;

    try {
      // 🧠 Fetch the record state BEFORE mutating it
      const preRes = await pool.query(
        "SELECT * FROM invitations WHERE id = $1 AND resident_id = $2",
        [id, user_id],
      );

      if (preRes.rows.length === 0) {
        return res.status(404).json({ error: "Invitation not found" });
      }

      const inviteBefore = preRes.rows[0];

      const query = `
      UPDATE invitations 
      SET is_cancelled = true 
      WHERE id = $1 AND resident_id = $2
      RETURNING *;
    `;
      const { rows } = await pool.query(query, [id, user_id]);
      const updatedInvite = rows[0];

      // 1. Respond instantly to resident client
      res.json({ message: "Invitation revoked", invitation: updatedInvite });

      // 2. Track access code cancellation asynchronously
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "VISITOR_PASS_REVOKED",
        target_resource: "invitations",
        target_id: id,
        description: `Resident cancelled entry pass for visitor "${inviteBefore.guest_name}". Authorization code invalid for entry.`,
        state_before: inviteBefore,
        state_after: updatedInvite,
        urgency: "HIGH",
      });
    } catch (err) {
      res.status(500).json({ error: "Failed to cancel invitation" });
    }
  },
);

router.patch(
  "/delete-history",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const { ids, estate_id: estateId } = req.body;
    const user_id = req.user.id;

    if (!Array.isArray(ids) || ids.length === 0) {
      return res
        .status(400)
        .json({ error: "A valid array of invitation IDs is required" });
    }

    try {
      // 1. Fetch all matching records before mutating them
      const preRes = await pool.query(
        "SELECT * FROM invitations WHERE id = ANY($1::uuid[]) AND resident_id = $2",
        [ids, user_id],
      );

      if (preRes.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "No matching invitations found or unauthorized" });
      }

      const recordsBefore = preRes.rows;
      const foundIds = recordsBefore.map((rec) => rec.id);

      // 2. Perform bulk update
      const updateQuery = `
        UPDATE invitations 
        SET is_cancelled = true 
        WHERE id = ANY($1::uuid[]) AND resident_id = $2
        RETURNING *;
      `;
      const { rows: updatedRows } = await pool.query(updateQuery, [
        foundIds,
        user_id,
      ]);

      // 3. Respond instantly to client
      res.json({
        message: `Successfully cancelled ${updatedRows.length} invitation(s)`,
        invitations: updatedRows,
      });

      // 4. Track access code cancellations asynchronously for each pass
      for (const updatedInvite of updatedRows) {
        const inviteBefore = recordsBefore.find(
          (r) => r.id === updatedInvite.id,
        );

        await createAppAuditLog(req, {
          estate_id: estateId || updatedInvite.estate_id,
          action_type: "VISITOR_PASS_REVOKED",
          target_resource: "invitations",
          target_id: updatedInvite.id,
          description: `Resident cancelled entry pass for visitor "${inviteBefore?.guest_name || "Guest"}". Authorization code invalid for entry.`,
          state_before: inviteBefore,
          state_after: updatedInvite,
          urgency: "HIGH",
        });
      }
    } catch (err) {
      console.error("Bulk Cancel Error:", err);
      res.status(500).json({ error: "Failed to cancel invitations" });
    }
  },
);

// -------------------- EDIT INVITATION WINDOW (LOGGED) --------------------
router.patch(
  "/edit/:id",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const { id } = req.params;
    const {
      start_date,
      end_date,
      start_time,
      end_time,
      excluded_dates,
      staff_position,
      is_activated,
      permitted_days,
      estate_id: estateId,
    } = req.body;

    const user_id = req.user.id;

    try {
      // 🧠 Fetch original operational values BEFORE updating fields
      const preCheck = await pool.query(
        "SELECT * FROM invitations WHERE id = $1 AND resident_id = $2",
        [id, user_id],
      );

      if (preCheck.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Invitation not found or unauthorized" });
      }

      const inviteStateBefore = preCheck.rows[0];

      const finalExclusions = Array.isArray(excluded_dates)
        ? JSON.stringify(excluded_dates)
        : JSON.stringify([]);
      const finalPermittedDays = Array.isArray(permitted_days)
        ? JSON.stringify(permitted_days)
        : JSON.stringify([]);

      const query = `
      UPDATE invitations 
      SET 
        start_date = COALESCE($1, start_date),
        end_date = COALESCE($2, end_date),
        start_time = COALESCE($3, start_time),
        end_time = COALESCE($4, end_time),
        excluded_dates = $5,
        staff_position = COALESCE($6, staff_position),
        is_activated = CASE WHEN $7::boolean IS NOT NULL THEN $7::boolean ELSE is_activated END,
        permitted_days = $8,
        status = CASE WHEN status = 'overstayed' THEN 'checked_in' ELSE status END
      WHERE id = $9 AND resident_id = $10
      RETURNING *;
    `;

      const { rows } = await pool.query(query, [
        start_date,
        end_date || null,
        start_time,
        end_time,
        finalExclusions,
        staff_position || null,
        is_activated !== undefined ? is_activated : null,
        finalPermittedDays,
        id,
        user_id,
      ]);

      const updatedInvite = rows[0];

      // 1. Respond instantly to user
      res.json({
        message: "Invitation updated successfully",
        invitation: updatedInvite,
      });

      // 2. Track schedule/validity criteria changes asynchronously
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "VISITOR_PASS_MODIFIED",
        target_resource: "invitations",
        target_id: id,
        description: `Resident reconfigured entry parameters or time windows for visitor "${inviteStateBefore.guest_name}".`,
        state_before: inviteStateBefore,
        state_after: updatedInvite,
        urgency: "HIGH",
      });
    } catch (err) {
      console.error("Update Error:", err);
      res.status(500).json({ error: "Failed to update invitation" });
    }
  },
);

// GET a single invitation by ID
router.post(
  "/verify",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyGuardActiveShift,
  async (req, res) => {
    const { code, estate_id } = req.body;
    try {
      const query = `
      SELECT 
        i.*, 
        u.name as resident_name, 
        u.locations,
        e.name as estate_name,
        e.lga,
        e.town,
        e.street_address
      FROM invitations i
      LEFT JOIN tenant_users u ON i.resident_id = u.id
      LEFT JOIN estates e ON i.estate_id = e.id
      WHERE i.access_code = $1 
        AND i.estate_id = $2
    `;

      const { rows } = await pool.query(query, [code, estate_id]);

      if (rows.length === 0) {
        return res.status(404).json({
          success: false,
          message: "No invitation matches this code for your estate.",
        });
      }

      res.json({
        success: true,
        invitation: rows[0],
      });
    } catch (err) {
      console.error("Fetch Error:", err);
      res.status(500).json({
        success: false,
        message: "Server error fetching invitation details",
      });
    }
  },
);

cron.schedule("0 2 * * *", async () => {
  try {
    const cleanupQuery = `
      DELETE FROM invitations 
      WHERE is_cancelled = true 
      OR status = 'checked_out'
      OR (status = 'pending' AND (end_date + end_time) < NOW() - INTERVAL '1 day');
    `;

    const result = await pool.query(cleanupQuery);
    console.log(
      `[Cleanup] Purged ${result.rowCount} expired/inactive records.`,
    );
  } catch (err) {
    console.error("Cleanup Cron Error:", err);
  }
});

const checkOverstays = async () => {
  console.log("Check Overstays");
  const client = await pool.connect();
  try {
    const overstayQuery = `
      SELECT 
        i.id, 
        i.guest_name, 
        i.estate_id, 
        i.resident_id, 
        u.push_token AS resident_token, 
        u.name AS resident_name,
        
        -- Aggregate all blocks into a comma-separated string (e.g., "Block A, Block B")
        COALESCE(
          (
            SELECT string_agg(DISTINCT (loc_elem->>'block'), ', ')
            FROM jsonb_array_elements(
              CASE 
                WHEN jsonb_typeof(u.locations->i.estate_id::text) = 'array' 
                THEN u.locations->i.estate_id::text 
                ELSE '[]'::jsonb 
              END
            ) AS loc_elem
          ), 
          'Unknown Block'
        ) AS resident_blocks,

        -- FIX: Use to_jsonb() around json_agg to properly cast the grouped results into text format
        COALESCE(
          (
            SELECT to_jsonb(json_agg(DISTINCT unit_elem.value))::text
            FROM jsonb_array_elements(
              CASE 
                WHEN jsonb_typeof(u.locations->i.estate_id::text) = 'array' 
                THEN u.locations->i.estate_id::text 
                ELSE '[]'::jsonb 
              END
            ) AS loc_elem,
            LATERAL jsonb_array_elements(loc_elem->'unit') AS unit_elem
          ),
          '[]'
        ) AS resident_units_json
        
      FROM invitations i
      JOIN tenant_users u ON i.resident_id = u.id
      WHERE i.status = 'checked_in' 
        AND i.is_cancelled = false
        AND (i.end_date + i.end_time) < NOW();
    `;

    const { rows: overstays } = await client.query(overstayQuery);
    if (overstays.length === 0) return;

    for (const record of overstays) {
      const alertTitle = "Overstay Alert 🚨";
      const residentBody = `${record.guest_name} has exceeded their stay time.`;

      // Parse out the aggregated units seamlessly
      let unitsDisplay = "Unknown Unit";
      try {
        const parsedUnits = JSON.parse(record.resident_units_json);
        if (Array.isArray(parsedUnits) && parsedUnits.length > 0) {
          unitsDisplay = parsedUnits.join(", ");
        }
      } catch (e) {
        console.error("Error parsing units string array", e);
      }

      // Output string cleanly handles single or multiple locations seamlessly!
      // e.g., "Invited by Simon (Block A, Block B, Unit 1, 4)"
      const securityAdminBody = `${record.guest_name} has overstayed. Invited by ${record.resident_name} (${record.resident_blocks}, Unit ${unitsDisplay}).`;

      const emergencyData = {
        type: "notification",
        subtype: "emergency",
        user_id: record.resident_id,
        message: residentBody,
      };

      // --- 1. RESIDENT LOGIC ---
      const resDb = await client.query(
        `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
         VALUES ($1, $2, 'tenant', $3, $4, 'emergency')
         RETURNING *`,
        [record.estate_id, record.resident_id, alertTitle, residentBody],
      );
      io.to(`user_${record.resident_id}`).emit(
        "new_notification",
        resDb.rows[0],
      );
      if (record.resident_token) {
        sendPushNotification(
          record.resident_token,
          alertTitle,
          residentBody,
          emergencyData,
        );
      }

      // --- 2. SECURITY LOGIC ---
      const { rows: onDutyGuards } = await client.query(
        "SELECT id, push_token FROM security_users WHERE estate_id = $1 AND is_on_duty = true",
        [record.estate_id],
      );

      for (const guard of onDutyGuards) {
        const guardDb = await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'security', $3, $4, 'emergency')
           RETURNING *`,
          [record.estate_id, guard.id, alertTitle, securityAdminBody],
        );
        io.to(`user_${guard.id}`).emit("new_notification", guardDb.rows[0]);
        if (guard.push_token) {
          sendPushNotification(
            guard.push_token,
            alertTitle,
            securityAdminBody,
            { ...emergencyData, user_id: guard.id },
          );
        }
      }

      // --- 3. ADMIN LOGIC ---
      const adminResult = await client.query(
        `SELECT eau.id 
         FROM estate_admin_users eau
         JOIN estates e ON e.root_admin_email = eau.email
         WHERE e.id = $1 
         LIMIT 1`,
        [record.estate_id],
      );

      if (adminResult.rows.length > 0) {
        const adminId = adminResult.rows[0].id;

        const adminDb = await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'admin', $3, $4, 'emergency')
           RETURNING *`,
          [record.estate_id, adminId, alertTitle, securityAdminBody],
        );

        const adminRoom = `admins_estate_${record.estate_id}`;
        io.to(adminRoom).emit("new_notification", adminDb.rows[0]);
      }
    }
  } catch (err) {
    console.error("Overstay Check Error:", err);
  } finally {
    client.release();
  }
};

export { checkOverstays };

export default router;
