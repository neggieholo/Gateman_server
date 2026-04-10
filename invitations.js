import express from "express";
import pool from "./db.js";
import { isAuth } from "./middlewares.js";
import crypto from "crypto";
import cron from "node-cron";
import { io } from "./server.js";


const router = express.Router();

// --- 1. GET ALL INVITATIONS ---
router.get("/", isAuth, async (req, res) => {
  const estate_id = req.user.estate_id;

  try {
    const query = `
      SELECT * FROM invitations 
      WHERE estate_id = $1
      ORDER BY created_at DESC;
    `;
    const { rows } = await pool.query(query, [estate_id]);
    // console.log("Invitations Retrieved:", rows.length);
    res.json(rows);
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to fetch invitations" });
  }
});


// --- 1. GET ALL INVITATIONS (FOR TRACK GUEST VIEW) ---
router.get("/resident", isAuth, async (req, res) => {
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
});

// --- 2. CREATE AN INVITATION (WITH SECURE CODE & EXCLUSIONS) ---
router.post("/", isAuth, async (req, res) => {
  console.log("Create Invitation Request Body:", req.body);
  const { 
    guest_name, 
    guest_image_url, 
    invite_type, 
    start_date, 
    end_date, 
    start_time, 
    end_time,
    excluded_dates 
  } = req.body;
  
  const estate_id = req.user.estate_id; 
  const resident_id = req.user.id;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Generate a secure 6-digit access code
    let accessCode;
    let isUnique = false;
    while (!isUnique) {
      accessCode = crypto.randomInt(100000, 999999).toString();
      const check = await client.query(
        "SELECT 1 FROM invitations WHERE access_code = $1 AND estate_id = $2 AND is_used = false",
        [accessCode, estate_id]
      );
      if (check.rows.length === 0) isUnique = true;
    }

    // Provision for excluded dates: optional regardless of type, but defaults to []
    const finalExclusions = Array.isArray(excluded_dates) 
      ? JSON.stringify(excluded_dates) 
      : JSON.stringify([]);

    const insertQuery = `
      INSERT INTO invitations (
        estate_id, resident_id, guest_name, guest_image_url, 
        access_code, invite_type, start_date, end_date, 
        start_time, end_time, excluded_dates
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11) 
      RETURNING *;
    `;

    const { rows } = await client.query(insertQuery, [
      estate_id, 
      resident_id, 
      guest_name, 
      guest_image_url || null, 
      accessCode, 
      invite_type, 
      start_date, 
      end_date, 
      start_time, 
      end_time, 
      finalExclusions 
    ]);

    await client.query("COMMIT");
    res.status(201).json(rows[0]);
  } catch (err) {
    if (client) await client.query("ROLLBACK");
    console.error("Invitation Error:", err);
    res.status(500).json({ error: "Failed to generate invitation" });
  } finally {
    client.release();
  }
});

// --- 4. LOG ACTIVITY (CHECK-IN / CHECK-OUT) ---
router.post("/log-activity/:id", isAuth, async (req, res) => {
  console.log("Log Activity Request Params:", req.params);
  const { id } = req.params;
  const { action } = req.body; // 'check_in' or 'check_out'
  const estate_id = req.user.estate_id;

  const now = new Date();
  const currentDate = now.toISOString().split('T')[0];
  const currentTime = now.toTimeString().split(' ')[0].substring(0, 5); // HH:mm

  try {
    // 1. Fetch current invitation state
    const inviteResult = await pool.query(
      "SELECT * FROM invitations WHERE id = $1 AND estate_id = $2",
      [id, estate_id]
    );

    if (inviteResult.rows.length === 0) {
      return res.status(404).json({ error: "Invitation not found" });
    }

    const invite = inviteResult.rows[0];

    // 2. Validation Guardrails
    if (invite.is_cancelled) return res.status(400).json({ error: "Invitation is cancelled" });
    
    // Check Exclusions for Multi-Entry
    if (invite.invite_type === 'multi_entry' && invite.excluded_dates?.includes(currentDate)) {
      return res.status(403).json({ error: "Access denied: Date is excluded" });
    }

    let updateQuery;
    let params;

    if (action === 'check_in') {
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
    } else if (action === 'check_out') {
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
    
    // Optional: Trigger a notification to the Resident
    // sendPushNotification(invite.resident_push_token, "Guest Update", `${invite.guest_name} has ${action === 'check_in' ? 'arrived' : 'departed'}.`);

    res.json({ message: `Guest ${action.replace('_', ' ')} successfully`, invitation: rows[0] });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to log activity" });
  }
});

// --- 3. DELETE AN INVITATION ---
// router.delete("/:id", isAuth, async (req, res) => {
//   const invite_id = req.params.id;
//   const user_id = req.user.id;

//   try {
//     const { rows } = await pool.query(
//       "DELETE FROM invitations WHERE id = $1 AND resident_id = $2 RETURNING *",
//       [invite_id, user_id]
//     );

//     if (rows.length === 0) {
//       return res.status(404).json({ error: "Invitation not found or unauthorized" });
//     }

//     res.json({ success: true, message: "Invitation cancelled" });
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Failed to delete invitation" });
//   }
// });

router.delete("/:id", isAuth, async (req, res) => {
  const { id } = req.params;
  const user_id = req.user.id;

  try {
    const query = `
      UPDATE invitations 
      SET is_cancelled = true 
      WHERE id = $1 AND resident_id = $2
      RETURNING *;
    `;
    const { rows } = await pool.query(query, [id, user_id]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "Invitation not found" });
    }
    
    res.json({ message: "Invitation revoked", invitation: rows[0] });
  } catch (err) {
    res.status(500).json({ error: "Failed to cancel invitation" });
  }
});

// --- EDIT/UPDATE AN INVITATION ---
router.patch("/edit/:id", isAuth, async (req, res) => {
  console.log("Edit Invitation Request Body:", req.body);
  const { id } = req.params;
  const { 
    start_date, 
    end_date, 
    start_time, 
    end_time, 
    excluded_dates 
  } = req.body;
  
  const user_id = req.user.id;

  try {
    // 1. Prepare exclusions (ensure it's always a JSON string for the DB)
    const finalExclusions = Array.isArray(excluded_dates) 
      ? JSON.stringify(excluded_dates) 
      : JSON.stringify([]);

    const query = `
      UPDATE invitations 
      SET 
        start_date = COALESCE($1, start_date),
        end_date = COALESCE($2, end_date),
        start_time = COALESCE($3, start_time),
        end_time = COALESCE($4, end_time),
        excluded_dates = $5,
        -- If it was 'overstayed' and we pushed the end_date/time forward, 
        -- we move it back to 'checked_in' status.
        status = CASE 
          WHEN status = 'overstayed' THEN 'checked_in' 
          ELSE status 
        END
      WHERE id = $6 AND resident_id = $7
      RETURNING *;
    `;

    const { rows } = await pool.query(query, [
      start_date, 
      end_date, 
      start_time, 
      end_time, 
      finalExclusions, 
      id, 
      user_id
    ]);
    
    if (rows.length === 0) {
      return res.status(404).json({ error: "Invitation not found or unauthorized" });
    }
    
    res.json({ 
      message: "Invitation updated successfully", 
      invitation: rows[0] 
    });
  } catch (err) {
    console.error("Update Error:", err);
    res.status(500).json({ error: "Failed to update invitation" });
  }
});

const sendPushNotification = async (token, title, body, data = {}) => {
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

// --- OVERSTAY ALERT ---
// cron.schedule('*/10 * * * *', async () => {
//   const client = await pool.connect(); 
//   try {
//     const overstayQuery = `
//       SELECT i.id, i.guest_name, i.estate_id, i.resident_id, u.push_token as resident_token
//       FROM invitations i
//       JOIN tenant_users u ON i.resident_id = u.id
//       WHERE i.status = 'checked_in' 
//       AND i.is_cancelled = false
//       AND (i.end_date + i.end_time) < NOW();
//     `;
    
//     const { rows: overstays } = await client.query(overstayQuery);
//     if (overstays.length === 0) return;

//     for (const record of overstays) {
//       const alertTitle = "Overstay Alert 🚨";
//       const alertBody = `${record.guest_name} has exceeded their stay time.`;

//       // --- 1. RESIDENT LOGIC ---
//       const resDb = await client.query(
//         `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
//          VALUES ($1, $2, 'tenant', $3, $4, 'emergency')
//          RETURNING *`, // <--- Get the full object back
//         [record.estate_id, record.resident_id, alertTitle, alertBody]
//       );

//       const residentNotif = resDb.rows[0];

//       // Real-time Push via Socket
//       io.to(`user_${record.resident_id}`).emit("new_notification", residentNotif);

//       // Firebase Push
//       if (record.resident_token) {
//         console.log('Sent Push to:', record.resident_id)
//         sendPushNotification(record.resident_token, alertTitle, alertBody, { type: "notification" });
//       }

//       // --- 2. SECURITY LOGIC ---
//       const { rows: onDutyGuards } = await client.query(
//         "SELECT id, push_token FROM security_users WHERE estate_id = $1 AND is_on_duty = true",
//         [record.estate_id]
//       );

//       for (const guard of onDutyGuards) {
//         const guardDb = await client.query(
//           `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
//            VALUES ($1, $2, 'security', $3, $4, 'emergency')
//            RETURNING *`,
//           [record.estate_id, guard.id, alertTitle, `[Duty Alert] ${alertBody}`]
//         );

//         const guardNotif = guardDb.rows[0];

//         // Real-time Push to Guard's Socket
//         io.to(`user_${guard.id}`).emit("new_notification", guardNotif);

//         if (guard.push_token) {
//           console.log('Sent Push to:', guard.id)
//           sendPushNotification(guard.push_token, alertTitle, `[Duty Alert] ${alertBody}`, { type: "notification" });
//         }
//       }

//       await client.query("UPDATE invitations SET status = 'overstayed' WHERE id = $1", [record.id]);
//     }
//   } catch (err) {
//     console.error("Overstay Cron Error:", err);
//   } finally {
//     client.release();
//   }
// });
// --- DELETE INVALID INVITATIONS ---
cron.schedule('0 2 * * *', async () => {
  try {
    const cleanupQuery = `
      DELETE FROM invitations 
      WHERE is_cancelled = true 
      OR status = 'checked_out'
      OR (status = 'pending' AND (end_date + end_time) < NOW() - INTERVAL '1 day');
    `;

    const result = await pool.query(cleanupQuery);
    console.log(`[Cleanup] Purged ${result.rowCount} expired/inactive records.`);
  } catch (err) {
    console.error("Cleanup Cron Error:", err);
  }
});

// 1. Define the logic as a named function
const checkOverstays = async () => {
  console.log("Check Overstays")
  const client = await pool.connect(); 
  try {
    const overstayQuery = `
      SELECT i.id, i.guest_name, i.estate_id, i.resident_id, u.push_token as resident_token
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
      const alertBody = `${record.guest_name} has exceeded their stay time.`;

      const emergencyData = {
        type: "notification",
        subtype: "emergency",
        user_id: record.resident_id, 
        message: alertBody,
      };

      // --- 1. RESIDENT LOGIC ---
      const resDb = await client.query(
        `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
         VALUES ($1, $2, 'tenant', $3, $4, 'emergency')
         RETURNING *`,
        [record.estate_id, record.resident_id, alertTitle, alertBody]
      );

      const residentNotif = resDb.rows[0];
      io.to(`user_${record.resident_id}`).emit("new_notification", residentNotif);

      if (record.resident_token) {
        console.log('Sent Push to:', record.resident_id);
        sendPushNotification(
          record.resident_token,
          alertTitle,
          alertBody,
          emergencyData,
        );
      }

      // --- 2. SECURITY LOGIC ---
      const { rows: onDutyGuards } = await client.query(
        "SELECT id, push_token FROM security_users WHERE estate_id = $1 AND is_on_duty = true",
        [record.estate_id]
      );

      for (const guard of onDutyGuards) {
        const guardDb = await client.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'security', $3, $4, 'emergency')
           RETURNING *`,
          [record.estate_id, guard.id, alertTitle, `[Duty Alert] ${alertBody}`]
        );

        const guardNotif = guardDb.rows[0];
        io.to(`user_${guard.id}`).emit("new_notification", guardNotif);

        if (guard.push_token) {
          console.log('Sent Push to:', guard.id);
          sendPushNotification(
            guard.push_token,
            alertTitle,
            `[Duty Alert] ${alertBody}`,
            { ...emergencyData, user_id: guard.id },
          );
        }
      }

      await client.query("UPDATE invitations SET status = 'overstayed' WHERE id = $1", [record.id]);
    }
  } catch (err) {
    console.error("Overstay Check Error:", err);
  } finally {
    client.release();
  }
};


export { checkOverstays };

export default router;