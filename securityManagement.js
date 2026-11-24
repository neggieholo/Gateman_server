import express from "express";
import pool from "./db.js";
import multer from "multer";
import {
  isAuth,
  verifyPermission,
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import { io } from "./server.js";
import { sendPushNotification } from "./invitations.js";
import {
  createAppAuditLog,
  calculateScheduleProjections,
  calculateSpecificShifts,
  formatDateString,
  verifyGuardActiveShift,
} from "./helpers.js";

const router = express.Router();

router.use(isAuth);

// -------------------- 1. Submit Security Join Request --------------------
router.post("/join-request", async (req, res) => {
  const tempSecurityId = req.user?.id;
  const { estateId, idType, selfieUrl, idFrontUrl, idBackUrl } = req.body;

  if (!tempSecurityId || !estateId || !selfieUrl || !idFrontUrl) {
    return res.status(400).json({
      error:
        "Missing user authentication, estate ID, or required document URLs.",
    });
  }

  try {
    const estateResult = await pool.query(
      "SELECT plan FROM estates WHERE id = $1",
      [estateId],
    );

    if (estateResult.rows.length === 0) {
      return res.status(404).json({
        success: false,
        error: "Estate not found.",
      });
    }

    const planData = estateResult.rows[0]?.plan;
    const plan =
      typeof planData === "string" ? JSON.parse(planData) : planData || {};
    const selectedAddOns = plan.selected_add_ons || [];

    const hasSecurityPlan = selectedAddOns.includes("security");

    if (!hasSecurityPlan) {
      return res.status(403).json({
        success: false,
        error: "This estate doesn't have a Security Feature enabled.",
      });
    }
    // 1. Prevent duplicate requests
    const existing = await pool.query(
      "SELECT id FROM security_join_requests WHERE temp_security_id = $1",
      [tempSecurityId],
    );
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: "Request already pending." });
    }

    // 2. Check restrictions
    const blockCheck = await pool.query(
      `SELECT id FROM estates 
       WHERE id = $1 AND $2 = ANY(blocked_security_ids)`,
      [estateId, tempSecurityId],
    );

    if (blockCheck.rows.length > 0) {
      return res.status(403).json({
        success: false,
        error:
          "Your application has been restricted by this estate's administration.",
      });
    }

    // 3. Clear rejection flag on user record
    await pool.query(
      "UPDATE temp_security_users SET rejection_message = NULL, is_read = FALSE WHERE id = $1",
      [tempSecurityId],
    );

    // 4. Save the S3 links into PostgreSQL directly
    const result = await pool.query(
      `INSERT INTO security_join_requests 
       (temp_security_id, estate_id, id_type, selfie_url, id_front_url, id_back_url)
       VALUES ($1, $2, $3, $4, $5, $6) RETURNING *`,
      [
        tempSecurityId,
        estateId,
        idType,
        selfieUrl,
        idFrontUrl,
        idBackUrl || null,
      ],
    );

    res.status(201).json({ success: true, joinRequest: result.rows[0] });
  } catch (err) {
    console.error("Join request database error:", err);
    res.status(500).json({ error: "Failed to submit security request." });
  }
});

// -------------------- Get Security Application Status --------------------
router.get("/my-request", async (req, res) => {
  const tempUserId = req.user.id;

  try {
    const activeRes = await pool.query(
      `SELECT sjr.*, e.name as estate_name 
       FROM security_join_requests sjr
       JOIN estates e ON sjr.estate_id = e.id
       WHERE sjr.temp_security_id = $1 AND sjr.status = 'PENDING'`,
      [tempUserId],
    );

    const userRes = await pool.query(
      "SELECT rejection_message, is_read FROM temp_security_users WHERE id = $1",
      [tempUserId],
    );

    res.json({
      success: true,
      activeRequest: activeRes.rows[0] || null,
      feedback: userRes.rows[0]?.rejection_message || null,
      isRead: userRes.rows[0]?.is_read ?? false,
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Server error" });
  }
});
// -------------------- Update Security Push Token --------------------
router.post("/update-push-token", async (req, res) => {
  const userId = req.user?.id;
  const role = req.user?.role;
  const { pushToken } = req.body;

  if (!userId || role !== "SECURITY") {
    return res.status(401).json({
      error: "Unauthorized: Only security personnel can update tokens here.",
    });
  }

  if (!pushToken) {
    return res.status(400).json({ error: "pushToken is required" });
  }

  try {
    const result = await pool.query(
      `UPDATE security_users 
       SET push_token = $1 
       WHERE id = $2 
       RETURNING id, name`,
      [pushToken, userId],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Security record not found" });
    }

    // console.log(`[Push Token] Updated for Guard: ${result.rows[0].name}`);

    res.json({
      success: true,
      message: "Security push token synchronized",
      user: result.rows[0],
    });
  } catch (err) {
    console.error("Security Push Token Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

// -------------------- 2. Fetch Security Requests (Admin View) --------------------
router.get(
  "/join-requests/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("view_guards", "security_management"),
  async (req, res) => {
    const estateId = req.params.estate_id;

    try {
      const result = await pool.query(
        `SELECT sjr.*, ts.name, ts.email, ts.phone
       FROM security_join_requests sjr
       JOIN temp_security_users ts ON sjr.temp_security_id = ts.id
       WHERE sjr.estate_id = $1 AND sjr.status = 'PENDING'
       ORDER BY sjr.requested_at DESC`,
        [estateId],
      );
      res.json({ success: true, requests: result.rows });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- 3. Approve Security (The Promotion) --------------------
router.post(
  "/approve/:requestId",
  ensureAdmin,
  verifyPermission("manage_guard_requests", "security_management"),
  async (req, res) => {
    const { requestId } = req.params;
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Get Request, User Info, and Estate Name
      const requestRes = await client.query(
        `SELECT sjr.*, ts.name, ts.email, ts.password, ts.phone, e.name AS estate_name 
         FROM security_join_requests sjr 
         JOIN temp_security_users ts ON sjr.temp_security_id = ts.id 
         JOIN estates e ON sjr.estate_id = e.id
         WHERE sjr.id = $1`,
        [requestId],
      );

      if (requestRes.rows.length === 0) {
        await client.query("ROLLBACK");
        client.release();
        return res.status(404).json({ error: "Request not found." });
      }

      const data = requestRes.rows[0];

      // 2. Insert into permanent security_users
      const insertRes = await client.query(
        `INSERT INTO security_users 
         (estate_id, name, email, password, phone, avatar, id_type, id_front_url, id_back_url, role)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'SECURITY') RETURNING id, name`,
        [
          data.estate_id,
          data.name,
          data.email,
          data.password,
          data.phone || null,
          data.selfie_url,
          data.id_type,
          data.id_front_url,
          data.id_back_url,
        ],
      );

      const newGuardId = insertRes.rows[0].id;
      const newGuardName = insertRes.rows[0].name;

      // 3. Cleanup Temp Records
      const feedbackObj = JSON.stringify({
        type: "approve",
        estate: data.estate_name,
        message: "Congratulations! You have been approved.",
      });

      await client.query(
        "UPDATE temp_security_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
        [feedbackObj, data.temp_security_id],
      );

      await client.query("DELETE FROM security_join_requests WHERE id = $1", [
        requestId,
      ]);

      await client.query("COMMIT");
      client.release();

      const { password: _, ...insertedGuardRow } = insertRes.rows[0];

      // 4. Dispatch Socket to the temp_security_id user room
      const notification = {
        from: data.estate_name,
        type: "announcement",
        message: "Congratulations! You have been approved.",
        reason: "Estate security join request approved.",
      };

      io.to(`user_${data.temp_security_id}`).emit(
        "status_update",
        notification,
      );

      // Audit log execution
      createAppAuditLog(req, {
        estate_id: data.estate_id,
        action_type: "GUARD_REQUEST_APPROVED",
        target_resource: "security_users",
        target_id: newGuardId,
        description: `Admin approved join request ID ${requestId}. Onboarded guard "${newGuardName}" (${data.email}) into permanent security systems.`,
        state_before: null,
        state_after: insertedGuardRow,
        urgency: "INFO",
      }).catch((auditErr) => console.error("Audit log error:", auditErr));

      return res.json({
        success: true,
        message: `${newGuardName} is now an official guard.`,
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      client.release();

      console.error("Promotion Error:", err);
      if (!res.headersSent) {
        return res.status(500).json({ error: "Promotion failed." });
      }
    }
  },
);

// -------------------- Decline Security Join Request --------------------
router.delete(
  "/join-request/delete",
  ensureAdmin,
  verifyPermission("manage_guard_requests", "security_management"),
  async (req, res) => {
    const { id, message } = req.body;

    try {
      const infoRes = await pool.query(
        `SELECT sjr.*, e.name as estate_name 
         FROM security_join_requests sjr 
         JOIN estates e ON sjr.estate_id = e.id 
         WHERE sjr.id = $1`,
        [id],
      );

      if (infoRes.rows.length === 0) {
        return res.status(404).json({ error: "Request not found." });
      }

      const requestData = infoRes.rows[0];
      const { temp_security_id, estate_name, estate_id } = requestData;

      const feedbackObj = JSON.stringify({
        type: "decline",
        estate: estate_name,
        message: message || "Your application was not approved at this time.",
      });

      await pool.query(
        "UPDATE temp_security_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
        [feedbackObj, temp_security_id],
      );

      await pool.query("DELETE FROM security_join_requests WHERE id = $1", [
        id,
      ]);

      res.json({ success: true, message: "Security request declined." });

      createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "GUARD_REQUEST_DECLINED",
        target_resource: "security_join_requests",
        target_id: id,
        description: `Admin declined guard join request ID ${id} for temporary security user ID ${temp_security_id}.`,
        state_before: requestData,
        state_after: null,
        urgency: "INFO",
      }).catch((auditErr) => console.error("Audit log error:", auditErr));
    } catch (err) {
      console.error("Decline request error:", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "Internal server error" });
      }
    }
  },
);

// -------------------- Block Security via Admin Table --------------------
router.put(
  "/join-request/block",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("manage_guard_requests", "security_management"),
  async (req, res) => {
    const { id, message, estate_id } = req.body;
    const adminId = req.user.id;

    try {
      // 🧠 Capture the admin's record BEFORE the block list modification
      const estateCheck = await pool.query(
        `SELECT id, email, blocked_security_ids FROM estates WHERE id = $1`,
        [estate_id],
      );
      const estateStateBefore = estateCheck.rows[0];

      const infoRes = await pool.query(
        `SELECT sjr.temp_security_id, sjr.name, e.name as estate_name 
        FROM security_join_requests sjr 
        JOIN estates e ON sjr.estate_id = e.id 
        WHERE sjr.id = $1`,
        [id],
      );

      if (infoRes.rows.length === 0)
        return res.status(404).json({ error: "Request not found" });

      const { temp_security_id, name, estate_name } = infoRes.rows[0];

      // 1. Add to Admin's Security Block List and return the updated array state
      const estateUpdateRes = await pool.query(
        `UPDATE estates 
        SET blocked_security_ids = array_append(blocked_security_ids, $1::uuid) 
        WHERE id = $2 AND NOT ($1::uuid = ANY(blocked_security_ids))
        RETURNING id, email, blocked_security_ids`,
        [temp_security_id, estate_id],
      );

      // Use updated state if array_append modified a row, otherwise use current state
      const estateStateAfter =
        estateUpdateRes.rowCount > 0
          ? estateUpdateRes.rows[0]
          : estateStateBefore;

      const feedbackObj = JSON.stringify({
        type: "block",
        estate: estate_name,
        message: message || "You have been restricted from this estate.",
      });

      await pool.query(
        "UPDATE temp_security_users SET rejection_message = $1, is_read = FALSE WHERE id = $2",
        [feedbackObj, temp_security_id],
      );

      await pool.query("DELETE FROM security_join_requests WHERE id = $1", [
        id,
      ]);

      // 2. Respond immediately
      res.json({ success: true, message: "Security user blocked." });

      // 3. Track footprints (Targeting the resource that mutated state permanently)
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "GUARD_REQUEST_BLOCKED",
        target_resource: "estates",
        target_id: estate_id,
        description: `Admin blacklisted temporary security user ${name} from joining the estate.`,
        state_before: estateStateBefore,
        state_after: estateStateAfter,
        urgency: "WARNING", // 👈 Elevated because blacklisting alters entry rules
      });
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Dismiss Security Notification --------------------
router.delete("/notification/dismiss", async (req, res) => {
  if (!req.user) {
    return res.status(401).json({ error: "Not authenticated" });
  }

  const userId = req.user.id;
  const isTemp = req.user.isTemp;

  try {
    if (isTemp) {
      await pool.query(
        "UPDATE temp_security_users SET rejection_message = NULL WHERE id = $1",
        [userId],
      );
      return res.json({ success: true, message: "Notification dismissed" });
    }
    res.json({
      success: true,
      message: "Action not required for permanent security",
    });
  } catch (err) {
    res.status(500).json({ error: "Internal server error" });
  }
});

// -------------------- Mark Security Notification as Read --------------------
router.put("/notification/read", async (req, res) => {
  const userId = req.user.id;
  if (req.user.isTemp) {
    await pool.query(
      "UPDATE temp_security_users SET is_read = TRUE WHERE id = $1",
      [userId],
    );
    return res.json({ success: true, message: "Notification marked as read" });
  }
  res.json({ success: true });
});

// -------------------- Fetch Blocked Guards --------------------
router.get(
  "/blocked-users/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("view_guards", "security_management"),
  async (req, res) => {
    const estateId = req.params.estate_id;

    try {
      const result = await pool.query(
        `SELECT id, name, email 
        FROM temp_security_users 
        WHERE id = ANY(
          SELECT unnest(blocked_security_ids) 
          FROM estates 
          WHERE id = $1
       )`,
        [estateId],
      );

      res.json({ success: true, blockedUsers: result.rows });
    } catch (err) {
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Unblock Security --------------------
router.put(
  "/join-request/unblock",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("manage_guard_requests", "security_management"),
  async (req, res) => {
    const { tempSecurityId, estate_id } = req.body;

    try {
      // 🧠 Capture the admin's state BEFORE removing the blocked security ID
      const estateCheck = await pool.query(
        `SELECT blocked_security_ids FROM estates WHERE id = $1`,
        [estate_id],
      );

      if (estateCheck.rowCount === 0) {
        return res.status(404).json({ error: "estate account not found" });
      }

      const estateStateBefore = estateCheck.rows[0];

      // 1. Update estate Block Array and return the mutation state inline
      const estateUpdateRes = await pool.query(
        `UPDATE estates 
        SET blocked_security_ids = array_remove(blocked_security_ids, $1::uuid) 
        WHERE id = $2
        RETURNING id, email, blocked_security_ids`,
        [tempSecurityId, estate_id],
      );

      const estateStateAfter =
        estateUpdateRes.rowCount > 0
          ? estateUpdateRes.rows[0]
          : estateStateBefore;

      // 2. Clear out the restriction notification flags
      await pool.query(
        "UPDATE temp_security_users SET rejection_message = NULL WHERE id = $1",
        [tempSecurityId],
      );

      // 3. Return response instantly
      res.json({ success: true, message: "Security guard unblocked." });

      // 4. Trace operational trail asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "GUARD_REQUEST_UNBLOCKED",
        target_resource: "estates",
        target_id: estate_id,
        description: `Admin removed restriction for temporary security user ID ${tempSecurityId}, allowing them to request to join again.`,
        state_before: estateStateBefore,
        state_after: estateStateAfter,
        urgency: "WARNING",
      });
    } catch (err) {
      console.error("Unblock Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Fetch All Security --------------------
router.post(
  "/tenant/all",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    try {
      const estateId = req.body.estate_id;
      const currentUserId = req.user?.id;

      if (!estateId) {
        return res
          .status(401)
          .json({ error: "Unauthorized: No estate assigned." });
      }

      let query;
      let params;

      query = `
        SELECT id, name, email, phone, avatar, estate_id, push_token, 
               is_on_duty, last_checkin, last_checkout, checkin_location, checkout_location,last_known_location
        FROM security_users 
        WHERE estate_id = $1 AND id != $2
        ORDER BY name ASC`;
      params = [estateId, currentUserId];

      const result = await pool.query(query, params);

      res.json({
        success: true,
        securityGuards: result.rows,
      });
    } catch (err) {
      console.error("Fetch security error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

router.get(
  "/all",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    try {
      const estateId = req.user?.estate_id;
      const currentUserId = req.user?.id;

      if (!estateId) {
        return res
          .status(401)
          .json({ error: "Unauthorized: No estate assigned." });
      }

      let query;
      let params;

      // If a Security Guard is fetching the list, hide their own record
      query = `
        SELECT id, name, email, phone, avatar, estate_id, push_token, 
               is_on_duty, last_checkin, last_checkout, checkin_location, checkout_location, last_known_location, checkin_address, checkout_address, last_known_address
        FROM security_users 
        WHERE estate_id = $1 AND id != $2
        ORDER BY name ASC`;
      params = [estateId, currentUserId];

      const result = await pool.query(query, params);

      res.json({
        success: true,
        securityGuards: result.rows,
      });
    } catch (err) {
      console.error("Fetch security error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

router.get(
  "/admin/all/:estate_id",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    try {
      const estateId = req.params?.estate_id;
      const currentUserId = req.user?.id;

      if (!estateId) {
        return res
          .status(401)
          .json({ error: "Unauthorized: No estate assigned." });
      }

      let query;
      let params;

      query = `
        SELECT id, name, email, phone, avatar, estate_id, push_token, 
               is_on_duty, id_type, id_front_url, id_back_url, last_checkin, last_checkout, checkin_location, checkout_location, last_known_location, last_location_time,last_liveness_photo_url, last_known_location_selfie, checkin_address, checkout_address, last_known_address
        FROM security_users 
        WHERE estate_id = $1 
        ORDER BY name ASC`;
      params = [estateId];

      const result = await pool.query(query, params);

      res.json({
        success: true,
        securityGuards: result.rows,
      });
    } catch (err) {
      console.error("Fetch security error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Delete Security Guard --------------------
router.delete(
  "/delete/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("delete_guard_account", "security_management"),
  async (req, res) => {
    const { id } = req.params;
    const { estate_id } = req.query;
    const admin_estate_id = estate_id;

    try {
      await pool.query("BEGIN");

      // 1. Fetch entire user profile data before deletion
      const dataRes = await pool.query(
        `SELECT 
        u.*, 
        e.name as estate_name
       FROM security_users u
       JOIN estates e ON e.id = $2
       WHERE u.id = $1`,
        [id, admin_estate_id],
      );

      if (dataRes.rows.length === 0) {
        await pool.query("ROLLBACK");
        return res
          .status(404)
          .json({ error: "Personnel or Estate context not found" });
      }

      const fullGuardData = dataRes.rows[0];
      const { name, email, password, phone, estate_name } = fullGuardData;

      const feedbackObj = JSON.stringify({
        type: "decline",
        estate: estate_name,
        message: "Your personnel access has been revoked.",
      });

      // 3. Insert into temp_security_users
      await pool.query(
        `INSERT INTO temp_security_users 
       (name, email, password, phone, rejection_message, is_read)
       VALUES ($1, $2, $3, $4, $5, FALSE)`,
        [name, email, password, phone, feedbackObj],
      );

      await pool.query("DELETE FROM security_users WHERE id = $1", [id]);

      await pool.query("COMMIT");

      res.json({
        success: true,
        message: `Personnel ${name} removed and notified via ${estate_name}.`,
      });

      const { password: _, ...safeStateBefore } = fullGuardData;

      await createAppAuditLog(req, {
        estate_id: admin_estate_id,
        action_type: "GUARD_DELETED",
        target_resource: "security_users",
        target_id: id,
        description: `Admin permanently offboarded security personnel "${name}" (${email}) and revoked all active system permissions.`,
        state_before: safeStateBefore,
        state_after: null,
        urgency: "WARNING",
      });
    } catch (err) {
      await pool.query("ROLLBACK");
      console.error("Removal Error:", err);
      res.status(500).json({ error: "Internal server error during removal" });
    }
  },
);

// -------------------- Security Check-In/Out Action --------------------
router.post(
  "/status-toggle",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    if (!req.user) {
      return res.status(401).json({ error: "Unauthorized. Please log in." });
    }

    const { location, livenessPhotoUrl } = req.body;
    const guardId = req.user.id;
    const estateId = req.user.estate_id;

    if (!livenessPhotoUrl) {
      return res.status(400).json({
        success: false,
        error: "Liveness verification photo is required.",
      });
    }

    const locString =
      location?.latitude && location?.longitude
        ? `${location.latitude.toFixed(6)}, ${location.longitude.toFixed(6)}`
        : "Unknown";
    const address = location?.address || null;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const guardRes = await client.query(
        "SELECT * FROM security_users WHERE id = $1 AND estate_id = $2 FOR UPDATE",
        [guardId, estateId],
      );

      if (guardRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({ error: "Guard not found" });
      }

      const guardStateBefore = guardRes.rows[0];
      const isOnDuty = guardStateBefore.is_on_duty;
      const nextDutyState = !isOnDuty;
      const actionType = nextDutyState ? "CHECK_IN" : "CHECK_OUT";

      // Root scope declarations for downstream logging
      const now = new Date();

      // Root scope variables for matched schedule tracking
      let matchedShift = null;
      let matchedProjectionId = null;

      // --- CHECK-IN VALIDATION GATE ---
      if (!isOnDuty) {
        const { rows: projections } = await client.query(
          `SELECT p.* 
          FROM estate_security_schedule_projections p
          JOIN estate_security_schedules s ON p.schedule_id = s.id
          WHERE s.estate_id = $1`,
          [estateId],
        );

        for (const proj of projections) {
          const shifts = [
            ...(proj.current_cycle_shifts || []),
            // ...(proj.next_cycle_shifts || []),
          ];

          const found = shifts.find((s) => {
            const guardList = s.assigned_guard_ids || [];
            const isAssigned =
              Array.isArray(guardList) && guardList.includes(guardId);
            if (!isAssigned) return false;

            // 2. Build Exact Local Datetime Boundaries
            const shiftStart = new Date(`${s.start_date}T${s.start_time}`);
            const shiftEnd = new Date(`${s.end_date}T${s.end_time}`);

            // 3. Exact Datetime Window Check
            return now >= shiftStart && now <= shiftEnd;
          });

          if (found) {
            matchedShift = {
              startTime: found.start_time,
              endTime: found.end_time,
            };
            matchedProjectionId = proj.id;
            break;
          }
        }

        // Reject check-in if no valid active shift is found
        if (!matchedShift) {
          await client.query("ROLLBACK");
          return res.status(403).json({
            success: false,
            error:
              "Check-in failed. You have no assigned shift scheduled at this time.",
          });
        }
      }

      // --- UPDATE GUARD STATE ---
      let guardStateAfter = null;
      const actualCheckinTime = !isOnDuty ? now : null;
      const actualCheckoutTime = isOnDuty ? now : null;

      if (!isOnDuty) {
        const updateRes = await client.query(
          `UPDATE security_users 
          SET is_on_duty = TRUE, 
              checkin_location = $1,
              last_known_location = $2,
              last_location_time = $3,
              last_checkin = $3,
              last_liveness_photo_url = $4,
              last_known_location_selfie = $4,
              checkin_address = $5,
              last_known_address = $5
          WHERE id = $6
          RETURNING *`,
          [
            locString,
            locString,
            actualCheckinTime,
            livenessPhotoUrl,
            address,
            guardId, // $6
          ],
        );
        guardStateAfter = updateRes.rows[0];
      } else {
        const updateRes = await client.query(
          `UPDATE security_users 
            SET is_on_duty = FALSE, 
                checkout_location = $1,
                last_known_location = $2,
                last_location_time = $3,
                last_checkout = $3,
                last_liveness_photo_url = $4,
                last_known_location_selfie = $4,
                checkout_address = $5,
                last_known_address = $5
            WHERE id = $6
            RETURNING *`,
            [
              locString,
              locString,
              actualCheckoutTime,
              livenessPhotoUrl,
              address,
              guardId, // $6
            ],
          );
          guardStateAfter = updateRes.rows[0];
      }

      // --- RECORD ENHANCED DUTY LOG ---
      await client.query(
        `INSERT INTO security_duty_logs 
          (guard_id, estate_id, action, location, address, liveness_photo_url, projection_id, expected_start_time, expected_end_time, actual_checkin_time, actual_checkout_time)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`,
        [
          guardId,
          estateId,
          actionType,
          locString,
          address,
          livenessPhotoUrl,
          matchedProjectionId,
          matchedShift ? matchedShift.startTime : null,
          matchedShift ? matchedShift.endTime : null,
          actualCheckinTime,
          actualCheckoutTime,
        ],
      );

      await client.query("COMMIT");

      res.json({ success: true, isOnDuty: nextDutyState });

      // Audit Logging
      const { password: _p1, ...safeBefore } = guardStateBefore;
      const { password: _p2, ...safeAfter } = guardStateAfter;
      const auditAction = isOnDuty
        ? "GUARD_SHIFT_ENDED"
        : "GUARD_SHIFT_STARTED";
      const statusPhrase = isOnDuty ? "checked-out from" : "checked-in to";

      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: auditAction,
        target_resource: "security_users",
        target_id: guardId,
        description: `Guard "${safeBefore.name}" successfully ${statusPhrase} duty shift at location [${locString}] (${address || "No address"}).`,
        state_before: safeBefore,
        state_after: safeAfter,
        urgency: "MEDIUM",
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("Toggle Error:", err);
      if (!res.headersSent) {
        res.status(500).json({ error: "Failed to toggle duty status." });
      }
    } finally {
      client.release();
    }
  },
);

// -------------------- Fetch Security Duty Logs --------------------
router.get(
  "/logs",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("view_security_logs", "logs_management"),
  async (req, res) => {
    const estateId = req.user.estate_id;

    try {
      const result = await pool.query(
        `SELECT 
        sl.id, 
        sl.checkin_time, 
        sl.checkout_time, 
        sl.checkin_location, 
        sl.checkout_location,
        s.name AS guard_name
       FROM security_logs sl
       JOIN security_users s ON sl.security_id = s.id
       WHERE s.estate_id = $1
       ORDER BY s.name ASC, sl.checkin_time DESC`,
        [estateId],
      );

      res.json({
        success: true,
        logs: result.rows,
      });
    } catch (err) {
      console.error("Fetch Security Logs Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// Request Guard Location (Admin Only)
router.post(
  "/request-guard-location/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const { guard_id } = req.body;
    const { id: adminId } = req.user;
    const { estate_id } = req.params;

    // console.log(
    //   "Location request for guard_id:",
    //   guard_id,
    //   "by admin_id:",
    //   adminId,
    // );

    const client = await pool.connect();
    try {
      const timestamp = new Date().toISOString();

      const guardRes = await client.query(
        `UPDATE security_users 
       SET ping = COALESCE(ping, '{}'::jsonb) || jsonb_build_object($1::text, $2::text)
       WHERE id = $3 AND estate_id = $4
       RETURNING name, push_token, ping`,
        [adminId, timestamp, guard_id, estate_id],
      );

      if (guardRes.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Guard not found in your estate." });
      }

      const guard = guardRes.rows[0];
      const title = "Location Request 📍";
      const message = "Admin has requested your current location photo.";

      // 2. Insert into notifications table for Guard
      const guardDb = await client.query(
        `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
       VALUES ($1, $2, 'security', $3, $4, 'emergency')
       RETURNING *`,
        [estate_id, guard_id, title, message],
      );

      const notificationRecord = guardDb.rows[0];

      // 3. Emit via Socket and send Push
      io.to(`user_${guard_id}`).emit("new_notification", notificationRecord);

      if (guard.push_token) {
        sendPushNotification(guard.push_token, title, message, {
          type: "notification",
          subtype: "location_ping",
          requested_by: adminId,
        });
      }

      // 4. Respond to admin client instantly
      res.json({
        success: true,
        message: `Location request sent to ${guard.name}`,
      });

      // 5. Audit Trace (Tracking the command footprint)
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "GUARD_LOCATION_PINGED",
        target_resource: "security_users", // The target entity being monitored
        target_id: guard_id,
        description: `Admin dispatched an explicit real-time location tracking request to guard "${guard.name}" (ID: ${guard_id}).`,
        state_before: null,
        state_after: {
          notification_id: notificationRecord.id,
          sent_via_push: !!guard.push_token,
        },
        urgency: "MEDIUM", // Elevated to MEDIUM due to location privacy tracking
      });
    } catch (err) {
      console.error("Location Request Error:", err);
      res.status(500).json({ error: "Failed to send request" });
    } finally {
      client.release();
    }
  },
);

router.post(
  "/update-location",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    if (
      !req.isAuthenticated ||
      !req.isAuthenticated() ||
      req.user.role !== "SECURITY"
    ) {
      return res
        .status(401)
        .json({ error: "Unauthorized: Security personnel only." });
    }

    const { latitude, longitude, address, selfie } = req.body;
    const guardId = req.user.id;
    const estateId = req.user.estate_id;

    if (!latitude || !longitude) {
      return res.status(400).json({ error: "Coordinates required." });
    }

    if (!selfie) {
      return res.status(400).json({ error: "Verification photo required." });
    }

    const locationString = `${latitude.toFixed(6)}, ${longitude.toFixed(6)}`;
    const knownAddress = address || null;

    try {
      await pool.query("BEGIN");

      // 1. Fetch state before update
      const guardRes = await pool.query(
        "SELECT * FROM security_users WHERE id = $1",
        [guardId],
      );

      if (guardRes.rows.length === 0) {
        await pool.query("ROLLBACK");
        return res.status(404).json({ error: "Guard not found." });
      }

      const guardStateBefore = guardRes.rows[0];

      // 2. Update Guard's record (Fixed trailing comma syntax error)
      const updateRes = await pool.query(
        `UPDATE security_users 
         SET last_known_location = $1, 
             last_known_location_selfie = $2,
             last_location_time = CURRENT_TIMESTAMP,
             last_known_address = $3
         WHERE id = $4
         RETURNING *`,
        [locationString, selfie, knownAddress, guardId],
      );

      const guardStateAfter = updateRes.rows[0];

      await pool.query("COMMIT");

      // 3. Fast response to mobile client
      res.json({ success: true, message: "Location & selfie synchronized" });

      // 4. Sanitize state objects before audit logging
      const { password: _p1, ...safeBefore } = guardStateBefore;
      const { password: _p2, ...safeAfter } = guardStateAfter;

      // 5. Document the location sync footprint via createAppAuditLog
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "GUARD_LOCATION_SYNC",
        target_resource: "security_users",
        target_id: guardId,
        description: `Guard "${safeBefore.name}" synchronized live location [${locationString}] (${knownAddress || "No address"}) with photo verification.`,
        state_before: safeBefore,
        state_after: safeAfter,
        urgency: "LOW",
      });

      // 6. Notify Estate Admin & emit real-time socket events
      const adminResult = await pool.query(
        "SELECT id FROM estate_admin_users WHERE estate_id = $1",
        [estateId],
      );

      if (adminResult.rows.length > 0) {
        const adminId = adminResult.rows[0].id;
        const adminTitle = "Location Updated";
        const adminMessage = `Guard ${safeBefore.name} updated their live location with verification photo.`;

        const adminDb = await pool.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'admin', $3, $4, 'announcement')
           RETURNING *`,
          [estateId, adminId, adminTitle, adminMessage],
        );

        io.to(`user_${adminId}`).emit("new_notification", adminDb.rows[0]);

        io.to(`estate_${estateId}`).emit("guard_location_update", {
          userId: guardId,
          guardName: safeBefore.name,
          location: locationString,
          address: knownAddress,
          selfie,
          updatedAt: new Date(),
        });
      }
    } catch (err) {
      await pool.query("ROLLBACK").catch(() => {});
      console.error("Location Update Error:", err);
      res.status(500).json({ error: "Failed to update location" });
    }
  },
);

// -------------------- Submit a Report (Resident/User) --------------------
router.post(
  "/report",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const {
      type,
      category,
      subject,
      description,
      payment_id,
      target_security_ids,
      estate_id,
    } = req.body;

    const reporter_id = req.user?.id;

    try {
      const query = `
      INSERT INTO estate_reports 
      (estate_id, reporter_id, type, category, subject, description, linked_payment_id, target_security_ids)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8) 
      RETURNING *`;

      const result = await pool.query(query, [
        estate_id,
        reporter_id,
        type,
        category,
        subject,
        description,
        payment_id || null, // Handles non-payment reports gracefully
        target_security_ids || [],
      ]);

      const newReport = result.rows[0];

      // 1. Respond instantly to the reporter client
      res.status(201).json({ success: true, report: newReport });

      // 2. Log incident dispatch tracking asynchronously
      const reporterName = req.user?.name
        ? `User "${req.user.name}"`
        : "A resident";

      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "REPORT_SUBMITTED",
        target_resource: "estate_reports",
        target_id: newReport.id,
        description: `${reporterName} filed a new ${type || "general"} report under category "${category}": ${subject}.`,
        state_before: null,
        state_after: newReport,
        urgency: "MEDIUM", // System visibility alert
      });
    } catch (err) {
      console.error("DB Error:", err.message);
      res.status(500).json({ error: "Failed to submit report" });
    }
  },
);

// -------------------- Fetch Reports (Admin View) --------------------
router.get(
  "/report/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("view_estate_reports", "estate_administration"),
  async (req, res) => {
    const estateId = req.params.estate_id;
    // console.log(`Fetching reports for estate_id: ${estateId} by admin_id: ${req.user.id}`);

    try {
      const result = await pool.query(
        `SELECT r.*, u.name as reporter_name 
       FROM estate_reports r
       JOIN tenant_users u ON r.reporter_id = u.id
       WHERE r.estate_id = $1
       ORDER BY r.created_at DESC`,
        [estateId],
      );

      res.json({ success: true, reports: result.rows });
    } catch (err) {
      console.error("Fetch Reports Error:", err);
      res.status(500).json({ error: "Internal server error" });
    }
  },
);

// -------------------- Fetch Personal Reports --------------------
router.post(
  "/my-reports",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const reporterId = req.user.id;
    const estateId = req.body.estate_id;

    try {
      const result = await pool.query(
        `SELECT * FROM estate_reports 
       WHERE reporter_id = $1 AND estate_id = $2
       ORDER BY created_at DESC`,
        [reporterId, estateId],
      );

      res.json({
        success: true,
        reports: result.rows,
      });
    } catch (err) {
      console.error("Fetch My Reports Error:", err);
      res.status(500).json({
        success: false,
        error: "Internal server error",
      });
    }
  },
);

// -------------------- Update Report Status --------------------
router.patch(
  "/report/status/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("modify_report_status", "estate_administration"),
  async (req, res) => {
    const { id } = req.params;
    const { status, admin_response, estate_id } = req.body;
    try {
      // 🧠 Fetch the pre-existing state before committing the update
      const initialCheck = await pool.query(
        `SELECT * FROM estate_reports WHERE id = $1 AND estate_id = $2`,
        [id, estate_id],
      );

      if (initialCheck.rowCount === 0) {
        return res.status(404).json({ error: "Report not found" });
      }

      const stateBefore = initialCheck.rows[0];

      // Execute the update
      const result = await pool.query(
        `UPDATE estate_reports 
       SET status = $1, 
           admin_response = $2
       WHERE id = $3 AND estate_id = $4 
       RETURNING *`,
        [status, admin_response || null, id, estate_id],
      );

      const stateAfter = result.rows[0];

      // 1. Respond to the front-end application instantly
      res.json({ success: true, report: stateAfter });

      // 2. Derive dynamic metadata strings cleanly
      const reportTypeNamespace = (stateBefore.type || "GENERAL")
        .toUpperCase()
        .trim();
      const dynamicActionType = `${reportTypeNamespace}_REPORT_STATUS_UPDATED`;

      const targetResourceTable = `estate_reports`;

      // 3. Track the action asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: dynamicActionType,
        target_resource: targetResourceTable,
        target_id: id,
        description: `Admin updated status of ${reportTypeNamespace.toLowerCase()} report ID ${id} ("${stateBefore.title || "No Title"}") from '${stateBefore.status.toUpperCase()}' to '${status.toUpperCase()}'.`,
        state_before: stateBefore,
        state_after: stateAfter,
        urgency: status === "resolved" ? "INFO" : "MEDIUM",
      });
    } catch (err) {
      console.error("Database Error:", err);
      res.status(500).json({ error: "Failed to update status and response" });
    }
  },
);

// -------------------- Delete Report (Resident Only) --------------------
router.delete("/my-reports/:id", async (req, res) => {
  try {
    const { id } = req.params;

    const result = await pool.query(
      "DELETE FROM estate_reports WHERE id = $1 AND reporter_id = $2 RETURNING *",
      [id, req.user.id],
    );

    if (result.rowCount === 0) {
      return res
        .status(404)
        .json({ success: false, error: "Report not found" });
    }

    const deletedReportData = result.rows[0];

    res.json({ success: true, message: "Deleted successfully" });

    const reportNamespace = (deletedReportData.type || "GENERAL")
      .toUpperCase()
      .trim();
    const dynamicActionType = `${reportNamespace}_REPORT_DELETED`;
    const targetResourceTable = `estate_reports`;

    await createAppAuditLog(req, {
      estate_id: deletedReportData.estate_id || req.user.estate_id || null,
      action_type: dynamicActionType,
      target_resource: targetResourceTable,
      target_id: id,
      description: `${req.user.name} deleted own filed ${reportNamespace.toLowerCase()} report: "${deletedReportData.title}".`,
      state_before: deletedReportData, // Preserves full textual details and URLs for audit verification
      state_after: null, // Purged from active storage
      urgency: "INFO", // Self-deletions rank as low-priority operational tracking
    });
  } catch (err) {
    console.error("Report Deletion Error:", err);
    res.status(500).json({ error: "Internal server error" });
  }
});

router.get(
  "/dashboard-stats",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    const { estate_id } = req.user;
    const today = new Date().toISOString().split("T")[0];

    try {
      // 1. Fetch Invitations active for today
      const inviteQuery = `
        SELECT 
          COUNT(*) FILTER (WHERE actual_checkin_date = CURRENT_DATE) as checked_in,
          COUNT(*) FILTER (WHERE actual_checkout_date = CURRENT_DATE) as checked_out,
          COUNT(*) FILTER (
            WHERE (start_date <= CURRENT_DATE AND end_date >= CURRENT_DATE)
            AND is_cancelled = false
            AND NOT (excluded_dates @> $2::jsonb)
          ) as total_expected_invites,
          COUNT(*) FILTER (
            WHERE actual_checkin_date = CURRENT_DATE 
            AND actual_checkout_time IS NULL 
            AND end_time < CURRENT_TIME
          ) as overstayed
        FROM invitations 
        WHERE estate_id = $1;
      `;

      // 2. Fetch Active Bookings Count (exact same WHERE condition as /bookings)
      const bookingsQuery = `
        SELECT 
          COUNT(*) as active_bookings_count
        FROM location_bookings
        WHERE estate_id = $1 
          AND status = 'APPROVED'
          AND start_date <= CURRENT_DATE 
          AND end_date >= CURRENT_DATE;
      `;

      const [inviteRes, eventRes] = await Promise.all([
        pool.query(inviteQuery, [estate_id, JSON.stringify(today)]),
        pool.query(bookingsQuery, [estate_id]),
      ]);

      const invites = inviteRes.rows[0];
      const activeCount = eventRes.rows?.[0]?.active_bookings_count;

      res.json({
        success: true,
        stats: {
          total_expected: parseInt(invites.total_expected_invites || 0, 10),
          checked_in: parseInt(invites.checked_in || 0, 10),
          checked_out: parseInt(invites.checked_out || 0, 10),
          overstayed: parseInt(invites.overstayed || 0, 10),
          active_bookings: activeCount ? parseInt(activeCount, 10) : 0,
        },
      });
    } catch (err) {
      console.error("Dashboard Sync Database Error:", err);
      res.status(500).json({ error: "Dashboard sync failed" });
    }
  },
);
// GET /api/bookings/today
router.get(
  "/bookings",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule(["security", "facility_bookings"]),
  verifyGuardActiveShift,
  async (req, res) => {
    const { estate_id } = req.user;

    try {
      const query = `
        SELECT 
          b.*,
          u.name AS resident_name,
          (u.avatar::jsonb)->>$1 AS resident_avatar
        FROM location_bookings b
        LEFT JOIN tenant_users u ON b.resident_id = u.id
        WHERE b.estate_id = $2 
          AND b.status = 'APPROVED'
          AND b.start_date <= CURRENT_DATE
          AND b.end_date >= CURRENT_DATE
        ORDER BY b.start_date ASC;
      `;

      // Pass estate_id twice: $1 for avatar key extraction, $2 for estate_id filter
      const { rows } = await pool.query(query, [estate_id, estate_id]);
      res.json({ success: true, bookings: rows });
    } catch (err) {
      console.error("Fetch Location Bookings Error:", err);
      res
        .status(500)
        .json({ success: false, error: "Failed to fetch approved location bookings" });
    }
  },
);

router.get(
  "/invitations",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyGuardActiveShift,
  async (req, res) => {
    const estate_id = req.user.estate_id;
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
        AND i.status != 'pending' -- Exclude those who haven't arrived at all
        AND (
          i.actual_checkin_date = CURRENT_DATE 
          OR i.actual_checkout_date = CURRENT_DATE
          OR i.status = 'checked_in' -- Include anyone still inside regardless of checkin date
        )
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

// ─── 1. FETCH ALL SECURITY SCHEDULES ───
router.get(
  "/schedules/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("view_security_schedules", "security_management"),
  async (req, res) => {
    const { estate_id } = req.params;

    try {
      const schedulesQuery = `
        SELECT 
          s.id,
          s.estate_id,
          s.name,
          s.mode,
          s.specific_date_groups,
          s.recurring_cadence,
          s.start_date,
          s.end_date,
          s.recurring_periods,
          s.created_at,
          s.updated_at,
          u.name AS created_by_name,
          u.email AS created_by_email,
          p.id AS projection_id,
          p.current_cycle_shifts,
          p.next_cycle_shifts,
          p.current_cycle_start_date,
          p.current_cycle_end_date,
          p.next_cycle_start_date,
          p.next_cycle_end_date,
          p.updated_at AS projection_updated_at
        FROM estate_security_schedules s
        LEFT JOIN estate_admin_users u ON s.created_by = u.id
        LEFT JOIN estate_security_schedule_projections p ON s.id = p.schedule_id
        WHERE s.estate_id = $1
        ORDER BY s.created_at DESC;
      `;

      // const result = await pool.query(query, [estate_id]);
      const guardsQuery = `
        SELECT id, name, email, phone, avatar, is_on_duty, status
        FROM security_users
        WHERE estate_id = $1;
      `;

      const [schedulesResult, guardsResult] = await Promise.all([
        pool.query(schedulesQuery, [estate_id]),
        pool.query(guardsQuery, [estate_id]),
      ]);

      // Safe parser to resolve single/double stringified JSON
      const parseJsonSafely = (data) => {
        if (!data) return null;
        let parsed = data;
        while (typeof parsed === "string") {
          try {
            parsed = JSON.parse(parsed);
          } catch (e) {
            break;
          }
        }
        return parsed;
      };

      const schedules = schedulesResult.rows.map((row) => {
        let dateGroups = parseJsonSafely(row.specific_date_groups);

        // Sort chronologically if it's a valid array
        if (Array.isArray(dateGroups)) {
          dateGroups.sort(
            (a, b) => new Date(a.date).getTime() - new Date(b.date).getTime(),
          );
        } else {
          dateGroups = [];
        }

        return {
          id: row.id,
          estate_id: row.estate_id,
          name: row.name,
          mode: row.mode,
          specific_date_groups: dateGroups,
          recurring_cadence: row.recurring_cadence,
          start_date: row.start_date,
          end_date: row.end_date,
          recurring_periods: parseJsonSafely(row.recurring_periods),
          created_at: row.created_at,
          updated_at: row.updated_at,
          created_by_name: row.created_by_name,
          created_by_email: row.created_by_email,
          projection: row.projection_id
            ? {
                id: row.projection_id,
                estate_id: row.estate_id,
                schedule_id: row.id,
                current_cycle_shifts: parseJsonSafely(row.current_cycle_shifts),
                next_cycle_shifts: parseJsonSafely(row.next_cycle_shifts),
                current_cycle_start_date: row.current_cycle_start_date,
                current_cycle_end_date: row.current_cycle_end_date,
                next_cycle_start_date: row.next_cycle_start_date,
                next_cycle_end_date: row.next_cycle_end_date,
                updated_at: row.projection_updated_at,
              }
            : null,
        };
      });

      return res.json({
        success: true,
        count: schedules.length,
        schedules,
        guardList: guardsResult.rows,
      });
    } catch (err) {
      console.error("Fetch Security Schedules Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error fetching security schedules.",
      });
    }
  },
);

// ─── 2. CREATE A NEW SECURITY SCHEDULE ───
router.post(
  "/schedules",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("add_security_schedule", "security_management"),
  async (req, res) => {
    const {
      estate_id,
      name,
      mode,
      specificDateGroups,
      recurringCadence,
      startDate,
      endDate,
      recurringPeriods,
    } = req.body;

    if (!estate_id || !name || !mode) {
      return res.status(400).json({
        success: false,
        message: "Missing core parameters (estate_id, name, mode).",
      });
    }

    if (mode === "specific" && !specificDateGroups?.length) {
      return res.status(400).json({
        success: false,
        message: "specificDateGroups are required when mode is 'specific'.",
      });
    }

    if (
      mode === "recurring" &&
      (!startDate || !recurringCadence || !recurringPeriods?.length)
    ) {
      return res.status(400).json({
        success: false,
        message:
          "startDate, recurring cadence, and recurring periods are required for recurring schedules.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Insert Core Schedule
      const insertScheduleQuery = `
        INSERT INTO estate_security_schedules (
          estate_id, name, mode, specific_date_groups,
          recurring_cadence, start_date, end_date, recurring_periods, created_by
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
        RETURNING *;
      `;

      const scheduleResult = await client.query(insertScheduleQuery, [
        estate_id,
        name.trim(),
        mode,
        specificDateGroups ? JSON.stringify(specificDateGroups) : null,
        recurringCadence || null,
        startDate || null,
        endDate || null,
        recurringPeriods ? JSON.stringify(recurringPeriods) : null,
        req.user.id,
      ]);

      const createdSchedule = scheduleResult.rows[0];

      // 2. Prepare Projection Parameters
      let currentShifts = [];
      let nextShifts = [];
      let currentCycleStart = null;
      let currentCycleEnd = null;
      let nextCycleStart = null;
      let nextCycleEnd = null;

      if (mode === "specific") {
        const specificData = calculateSpecificShifts(specificDateGroups);

        const todayStr = new Date().toISOString().split("T")[0];
        currentShifts = specificData.shifts;
        currentCycleStart = specificData.startDate || todayStr;
        currentCycleEnd = specificData.endDate || currentCycleStart;
        nextShifts = [];
      } else if (mode === "recurring") {
        const projections = calculateScheduleProjections(
          startDate,
          recurringCadence,
          recurringPeriods,
          endDate || null,
        );

        currentShifts = projections.currentShifts;
        nextShifts = projections.nextShifts;
        currentCycleStart = projections.currentCycleStartDate;
        currentCycleEnd = projections.currentCycleEndDate;
        nextCycleStart = projections.nextCycleStartDate;
        nextCycleEnd = projections.nextCycleEndDate;
      }

      // 3. Insert Projection Record
      const insertProjectionQuery = `
        INSERT INTO estate_security_schedule_projections (
          estate_id,
          schedule_id,
          current_cycle_shifts,
          next_cycle_shifts,
          current_cycle_start_date,
          current_cycle_end_date,
          next_cycle_start_date,
          next_cycle_end_date
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        RETURNING *;
      `;

      const projectionResult = await client.query(insertProjectionQuery, [
        estate_id,
        createdSchedule.id,
        JSON.stringify(currentShifts),
        JSON.stringify(nextShifts),
        currentCycleStart,
        currentCycleEnd,
        nextCycleStart,
        nextCycleEnd,
      ]);

      const createdProjection = projectionResult.rows[0];

      await client.query("COMMIT");

      // 4. Construct complete response object matching FetchedSecuritySchedule
      const responseSchedule = {
        id: createdSchedule.id,
        estate_id: createdSchedule.estate_id,
        name: createdSchedule.name,
        mode: createdSchedule.mode,
        specific_date_groups: createdSchedule.specific_date_groups,
        recurring_cadence: createdSchedule.recurring_cadence,
        start_date: createdSchedule.start_date,
        end_date: createdSchedule.end_date,
        recurring_periods: createdSchedule.recurring_periods,
        created_at: createdSchedule.created_at,
        updated_at: createdSchedule.updated_at,
        created_by_name: req.user.name || null,
        created_by_email: req.user.email || null,
        projection: {
          id: createdProjection.id,
          estate_id: createdProjection.estate_id,
          schedule_id: createdProjection.schedule_id,
          current_cycle_shifts: createdProjection.current_cycle_shifts,
          next_cycle_shifts: createdProjection.next_cycle_shifts,
          current_cycle_start_date: createdProjection.current_cycle_start_date,
          current_cycle_end_date: createdProjection.current_cycle_end_date,
          next_cycle_start_date: createdProjection.next_cycle_start_date,
          next_cycle_end_date: createdProjection.next_cycle_end_date,
          updated_at: createdProjection.updated_at,
        },
      };

      await createAppAuditLog(req, {
        action_type: "CREATE_SECURITY_SCHEDULE",
        target_resource: "estate_security_schedules",
        target_id: createdSchedule.id,
        description: `Created ${mode} security schedule: "${createdSchedule.name}"`,
        state_before: null,
        state_after: {
          schedule: responseSchedule,
        },
        log_type: "user",
      });

      return res.status(201).json({
        success: true,
        message: "Security schedule and projections created successfully.",
        schedule: responseSchedule,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Save Security Schedule Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error creating security schedule.",
      });
    } finally {
      client.release();
    }
  },
);

// ─── 3. EDIT A SECURITY SCHEDULE ───
router.put(
  "/schedules/:scheduleId",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("edit_security_schedule", "security_management"),
  async (req, res) => {
    const { scheduleId } = req.params;
    const { estate_id, name, endDate } = req.body;

    if (!estate_id || !name) {
      return res.status(400).json({
        success: false,
        message: "Missing required payload parameters (estate_id, name).",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Fetch current schedule state
      const snapshotResult = await client.query(
        "SELECT * FROM estate_security_schedules WHERE id = $1 AND estate_id = $2",
        [scheduleId, estate_id],
      );

      if (snapshotResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message: "Target security schedule not found.",
        });
      }

      const previousSchedule = snapshotResult.rows[0];
      const newEndDate =
        endDate !== undefined ? endDate || null : previousSchedule.end_date;

      // 2. Update core schedule fields
      const updateQuery = `
        UPDATE estate_security_schedules
        SET 
          name = $1,
          end_date = $2,
          updated_at = NOW()
        WHERE id = $3 AND estate_id = $4
        RETURNING *;
      `;

      const scheduleResult = await client.query(updateQuery, [
        name.trim(),
        newEndDate,
        scheduleId,
        estate_id,
      ]);

      const updatedSchedule = scheduleResult.rows[0];

      // 3. Handle Projection recalculation if end_date changed in recurring mode
      let updatedProjection = null;
      const endDateChanged = previousSchedule.end_date !== newEndDate;

      if (updatedSchedule.mode === "recurring" && endDateChanged) {
        // Safe parser helper
        const parseJsonSafely = (data) => {
          if (!data) return null;
          let parsed = data;
          while (typeof parsed === "string") {
            try {
              parsed = JSON.parse(parsed);
            } catch (e) {
              break;
            }
          }
          return parsed;
        };

        // Fetch existing projection snapshot for current anchor dates
        const currentProjResult = await client.query(
          "SELECT * FROM estate_security_schedule_projections WHERE schedule_id = $1 AND estate_id = $2",
          [scheduleId, estate_id],
        );

        const currentProjRow = currentProjResult.rows[0];

        // Use the active projection cycle start date, falling back to core schedule start_date
        const projectionStartDate = currentProjRow?.current_cycle_start_date
          ? formatDateString(currentProjRow.current_cycle_start_date)
          : formatDateString(updatedSchedule.start_date);

        // Target new end date provided in request, falling back to projection or schedule end_date
        const projectionEndDate = formatDateString(newEndDate);

        const recurringPeriods =
          parseJsonSafely(updatedSchedule.recurring_periods) || [];

        // Calculate new projections anchored to current cycle start date
        const projections = calculateScheduleProjections(
          projectionStartDate,
          updatedSchedule.recurring_cadence,
          recurringPeriods,
          projectionEndDate,
        );

        const updateProjectionQuery = `
          UPDATE estate_security_schedule_projections
          SET 
            current_cycle_shifts = $1,
            next_cycle_shifts = $2,
            current_cycle_start_date = $3,
            current_cycle_end_date = $4,
            next_cycle_start_date = $5,
            next_cycle_end_date = $6,
            updated_at = NOW()
          WHERE schedule_id = $7 AND estate_id = $8
          RETURNING *;
        `;

        const projResult = await client.query(updateProjectionQuery, [
          JSON.stringify(projections.currentShifts),
          JSON.stringify(projections.nextShifts),
          projections.currentCycleStartDate,
          projections.currentCycleEndDate,
          projections.nextCycleStartDate,
          projections.nextCycleEndDate,
          scheduleId,
          estate_id,
        ]);

        if (projResult.rows.length > 0) {
          const rawProj = projResult.rows[0];
          updatedProjection = {
            id: rawProj.id,
            estate_id: rawProj.estate_id,
            schedule_id: rawProj.schedule_id,
            current_cycle_shifts: parseJsonSafely(rawProj.current_cycle_shifts),
            next_cycle_shifts: parseJsonSafely(rawProj.next_cycle_shifts),
            current_cycle_start_date: rawProj.current_cycle_start_date,
            current_cycle_end_date: rawProj.current_cycle_end_date,
            next_cycle_start_date: rawProj.next_cycle_start_date,
            next_cycle_end_date: rawProj.next_cycle_end_date,
            updated_at: rawProj.updated_at,
          };
        }
      }

      await createAppAuditLog(req, {
        action_type: "UPDATE_SECURITY_SCHEDULE",
        target_resource: "estate_security_schedules",
        target_id: updatedSchedule.id,
        description: `Updated security schedule: "${updatedSchedule.name}"`,
        state_before: previousSchedule,
        state_after: updatedSchedule,
        log_type: "user",
      });

      await client.query("COMMIT");

      return res.json({
        success: true,
        message: "Security schedule updated successfully.",
        schedule: updatedSchedule,
        projection: updatedProjection,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Update Security Schedule Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error updating security schedule.",
      });
    } finally {
      client.release();
    }
  },
);

router.put(
  "/schedules/:scheduleId/assign-slot",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("edit_security_schedule", "security_management"),
  async (req, res) => {
    const { scheduleId } = req.params;
    const { estate_id, periodId, assignedGuardIds, dateStr } = req.body;

    if (!estate_id || !periodId || !Array.isArray(assignedGuardIds)) {
      return res.status(400).json({
        success: false,
        message:
          "Missing required parameters (estate_id, periodId, assignedGuardIds).",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Fetch current schedule
      const snapshotResult = await client.query(
        "SELECT * FROM estate_security_schedules WHERE id = $1 AND estate_id = $2",
        [scheduleId, estate_id],
      );

      if (snapshotResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message: "Target security schedule not found.",
        });
      }

      const schedule = snapshotResult.rows[0];

      const parseJsonSafely = (data) => {
        if (!data) return null;
        let parsed = data;
        while (typeof parsed === "string") {
          try {
            parsed = JSON.parse(parsed);
          } catch (e) {
            break;
          }
        }
        return parsed;
      };

      let updatedSpecificGroups = parseJsonSafely(
        schedule.specific_date_groups,
      );
      let updatedRecurringPeriods = parseJsonSafely(schedule.recurring_periods);

      // 2. Modify targeted period based on mode
      if (
        schedule.mode === "specific" &&
        Array.isArray(updatedSpecificGroups)
      ) {
        if (!dateStr) {
          await client.query("ROLLBACK");
          return res.status(400).json({
            success: false,
            message: "dateStr is required for specific mode slot reassignment.",
          });
        }

        updatedSpecificGroups = updatedSpecificGroups.map((group) => {
          if (group.date === dateStr) {
            return {
              ...group,
              periods: (group.periods || []).map((p) =>
                p.id === periodId ? { ...p, assignedGuardIds } : p,
              ),
            };
          }
          return group;
        });
      } else if (
        schedule.mode === "recurring" &&
        Array.isArray(updatedRecurringPeriods)
      ) {
        updatedRecurringPeriods = updatedRecurringPeriods.map((p) =>
          p.id === periodId ? { ...p, assignedGuardIds } : p,
        );
      }

      // 3. Save updated periods to DB
      const updateScheduleQuery = `
        UPDATE estate_security_schedules
        SET 
          specific_date_groups = $1,
          recurring_periods = $2,
          updated_at = NOW()
        WHERE id = $3 AND estate_id = $4
        RETURNING *;
      `;

      const scheduleResult = await client.query(updateScheduleQuery, [
        updatedSpecificGroups ? JSON.stringify(updatedSpecificGroups) : null,
        updatedRecurringPeriods
          ? JSON.stringify(updatedRecurringPeriods)
          : null,
        scheduleId,
        estate_id,
      ]);

      const updatedScheduleRow = scheduleResult.rows[0];

      // 4. Update projections using existing projection cycle dates
      let updatedProjection = null;
      let currentShifts = [];
      let nextShifts = [];
      let currentCycleStart = null;
      let currentCycleEnd = null;
      let nextCycleStart = null;
      let nextCycleEnd = null;

      // Fetch current projection snapshot to preserve cycle anchor dates
      const currentProjResult = await client.query(
        "SELECT * FROM estate_security_schedule_projections WHERE schedule_id = $1 AND estate_id = $2",
        [scheduleId, estate_id],
      );

      const currentProjRow = currentProjResult.rows[0];

      // Fallback to core schedule start/end date if projection row doesn't exist yet
      const projectionStartDate = currentProjRow?.current_cycle_start_date
        ? formatDateString(currentProjRow.current_cycle_start_date)
        : formatDateString(updatedScheduleRow.start_date);

      const projectionEndDate = formatDateString(updatedScheduleRow.end_date);

      if (updatedScheduleRow.mode === "specific") {
        const specificData = calculateSpecificShifts(updatedSpecificGroups);

        const todayStr = new Date().toISOString().split("T")[0];
        currentShifts = specificData.shifts;
        currentCycleStart = specificData.startDate || todayStr;
        currentCycleEnd = specificData.endDate || currentCycleStart;
        nextShifts = [];
      } else if (updatedScheduleRow.mode === "recurring") {
        const projections = calculateScheduleProjections(
          projectionStartDate,
          updatedScheduleRow.recurring_cadence,
          updatedRecurringPeriods,
          projectionEndDate,
        );

        currentShifts = projections.currentShifts;
        nextShifts = projections.nextShifts;
        currentCycleStart = projections.currentCycleStartDate;
        currentCycleEnd = projections.currentCycleEndDate;
        nextCycleStart = projections.nextCycleStartDate;
        nextCycleEnd = projections.nextCycleEndDate;
      }

      const updateProjectionQuery = `
          UPDATE estate_security_schedule_projections
          SET 
            current_cycle_shifts = $1,
            next_cycle_shifts = $2,
            current_cycle_start_date = $3,
            current_cycle_end_date = $4,
            next_cycle_start_date = $5,
            next_cycle_end_date = $6,
            updated_at = NOW()
          WHERE schedule_id = $7 AND estate_id = $8
          RETURNING *;
        `;

      const projResult = await client.query(updateProjectionQuery, [
        JSON.stringify(currentShifts),
        JSON.stringify(nextShifts),
        currentCycleStart,
        currentCycleEnd,
        nextCycleStart,
        nextCycleEnd,
        scheduleId,
        estate_id,
      ]);

      if (projResult.rows.length > 0) {
        const rawProj = projResult.rows[0];
        updatedProjection = {
          id: rawProj.id,
          estate_id: rawProj.estate_id,
          schedule_id: rawProj.schedule_id,
          current_cycle_shifts: parseJsonSafely(rawProj.current_cycle_shifts),
          next_cycle_shifts: parseJsonSafely(rawProj.next_cycle_shifts),
          current_cycle_start_date: rawProj.current_cycle_start_date,
          current_cycle_end_date: rawProj.current_cycle_end_date,
          next_cycle_start_date: rawProj.next_cycle_start_date,
          next_cycle_end_date: rawProj.next_cycle_end_date,
          updated_at: rawProj.updated_at,
        };
      }

      await client.query("COMMIT");

      return res.json({
        success: true,
        message: "Slot guard reassignment updated successfully.",
        specific_date_groups: parseJsonSafely(
          updatedScheduleRow.specific_date_groups,
        ),
        recurring_periods: parseJsonSafely(
          updatedScheduleRow.recurring_periods,
        ),
        projection: updatedProjection,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Assign Slot Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error updating slot assignment.",
      });
    } finally {
      client.release();
    }
  },
);

// POST /api/security/schedules/:scheduleId/projection-override
router.post(
  "/schedules/projection-override:projectionId",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("edit_security_schedule", "security_management"),
  async (req, res) => {
    const { projectionId } = req.params;
    const { estate_id, periodId, cycle, assignedGuardIds } = req.body;

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Query by primary key id (projectionId)
      const { rows } = await client.query(
        `SELECT id, schedule_id, current_cycle_shifts, next_cycle_shifts 
         FROM estate_security_schedule_projections 
         WHERE id = $1 AND estate_id = $2 LIMIT 1`,
        [projectionId, estate_id],
      );

      if (rows.length === 0) {
        await client.query("ROLLBACK");
        return res
          .status(404)
          .json({ success: false, message: "Projection not found" });
      }

      const projection = rows[0];
      const targetKey =
        cycle === "next" ? "next_cycle_shifts" : "current_cycle_shifts";
      const shiftsList = projection[targetKey] || [];

      // Cycle through array and update matching period_id
      let updated = false;
      const updatedShifts = shiftsList.map((shift) => {
        if (shift.period_id === periodId) {
          updated = true;
          return { ...shift, assigned_guard_ids: assignedGuardIds };
        }
        return shift;
      });

      if (!updated) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message: `Period ID '${periodId}' not found in ${cycle} cycle shifts`,
        });
      }

      // Save updated JSON array back to DB
      const updateQuery = `
        UPDATE estate_security_schedule_projections
        SET ${targetKey} = $1::jsonb,
            updated_at = NOW()
        WHERE id = $2
        RETURNING *;
      `;

      await client.query(updateQuery, [
        JSON.stringify(updatedShifts),
        projection.id,
      ]);

      await client.query("COMMIT");

      return res.json({ success: true });
    } catch (error) {
      await client.query("ROLLBACK");
      console.error("Failed to update projection shift:", error);
      return res.status(500).json({ success: false, message: "Server error" });
    } finally {
      client.release();
    }
  },
);

// ─── 4. DELETE A SECURITY SCHEDULE ───
router.delete(
  "/schedules/:scheduleId",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPermission("delete_security_schedule", "security_management"),
  async (req, res) => {
    const { scheduleId } = req.params;
    const estateId = req.query.estate_id || req.body.estate_id;
    if (!estateId) {
      return res.status(400).json({
        success: false,
        message: "Missing estate_id parameter.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const checkResult = await client.query(
        "SELECT * FROM estate_security_schedules WHERE id = $1 AND estate_id = $2",
        [scheduleId, estateId],
      );

      if (checkResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message: "Target security schedule not found.",
        });
      }

      const targetSchedule = checkResult.rows[0];

      await client.query(
        "DELETE FROM estate_security_schedules WHERE id = $1 AND estate_id = $2",
        [scheduleId, estateId],
      );

      await createAppAuditLog(req, {
        action_type: "DELETE_SECURITY_SCHEDULE",
        target_resource: "estate_security_schedules",
        target_id: scheduleId,
        description: `Deleted security schedule: "${targetSchedule.name}"`,
        state_before: targetSchedule,
        state_after: null,
        log_type: "user",
      });

      await client.query("COMMIT");

      return res.json({
        success: true,
        message: `Security schedule "${targetSchedule.name}" deleted successfully.`,
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Delete Security Schedule Failure:", err);
      return res.status(500).json({
        success: false,
        message: "Internal server error purging security schedule.",
      });
    } finally {
      client.release();
    }
  },
);

// GET /api/security/duty-logs/:estateId
router.get(
  "/duty-logs/:estateId",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  verifyPermission("view_security_logs", "logs_management"),
  async (req, res) => {
    const { estateId } = req.params;
    const client = await pool.connect();

    try {
      const query = `
        SELECT 
          l.id,
          l.guard_id,
          u.name AS guard_name,
          u.email AS guard_email,
          l.estate_id,
          l.action,
          l.location,
          l.address,
          l.liveness_photo_url,
          l.projection_id,
          s.name AS schedule_name,
          l.expected_start_time,
          l.expected_end_time,
          l.actual_checkin_time,
          l.actual_checkout_time,
          l.created_at
        FROM security_duty_logs l
        LEFT JOIN security_users u 
          ON l.guard_id = u.id
        LEFT JOIN estate_security_schedule_projections p 
          ON l.projection_id = p.id
        LEFT JOIN estate_security_schedules s 
          ON p.schedule_id = s.id
        WHERE l.estate_id = $1
        ORDER BY l.created_at DESC
      `;

      const { rows } = await client.query(query, [estateId]);

      res.json({
        success: true,
        logs: rows,
      });
    } catch (err) {
      console.error("Fetch Duty Logs Error:", err);
      res.status(500).json({ error: "Failed to fetch security duty logs." });
    } finally {
      client.release();
    }
  },
);

router.get(
  "/my-schedules",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("security"),
  async (req, res) => {
    try {
      const guardId = req.user?.id;
      const estateId = req.user?.estate_id;

      if (!guardId || !estateId) {
        return res.status(401).json({
          success: false,
          error: "Unauthorized. Missing guard identity or estate context.",
        });
      }

      // Query projections for the guard's estate
      const { rows: projections } = await pool.query(
        `SELECT p.current_cycle_shifts, p.next_cycle_shifts
       FROM estate_security_schedule_projections p
       JOIN estate_security_schedules s ON p.schedule_id = s.id
       WHERE s.estate_id = $1`,
        [estateId],
      );

      const guardShifts = [];

      // Extract shifts where guard is assigned
      for (const proj of projections) {
        const allShifts = [
          ...(proj.current_cycle_shifts || []),
          ...(proj.next_cycle_shifts || []),
        ];

        for (const shift of allShifts) {
          const guardList = shift.assigned_guard_ids || [];
          if (Array.isArray(guardList) && guardList.includes(guardId)) {
            guardShifts.push({
              period_id: shift.period_id || null,
              label: shift.label || "",
              start_date: shift.start_date,
              start_time: shift.start_time,
              end_date: shift.end_date,
              end_time: shift.end_time,
              assigned_guard_ids: guardList,
            });
          }
        }
      }

      // Order chronologically by start date & time
      guardShifts.sort((a, b) => {
        const dateA = new Date(`${a.start_date}T${a.start_time}`).getTime();
        const dateB = new Date(`${b.start_date}T${b.start_time}`).getTime();
        return dateA - dateB;
      });

      return res.status(200).json({ success: false, shifts: guardShifts });
    } catch (error) {
      console.error("Error retrieving guard shifts:", error);
      return res.status(500).json({
        success: false,
        error: "Failed to retrieve guard shifts.",
      });
    }
  },
);

export default router;
