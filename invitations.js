import express from "express";
import pool from "./db.js";
import { isAuth } from "./middlewares.js";
import crypto from "crypto";
import cron from "node-cron";
const router = express.Router();

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

// cron.schedule('*/10 * * * *', async () => {
//   try {
//     const query = `
//       SELECT i.id, i.guest_name, u.push_token 
//       FROM invitations i
//       JOIN tenant_users u ON i.resident_id = u.id
//       WHERE i.status = 'checked_in' 
//       AND i.is_cancelled = false
//       AND (i.end_date + i.end_time) < NOW();
//     `;
    
//     const { rows } = await pool.query(query);
//     if (rows.length === 0) return;

//     // Process all notifications in parallel
//     await Promise.all(rows.map(async (invitation) => {
//       if (invitation.push_token) {
//         try {
//           await sendPushNotification(
//             invitation.push_token,
//             "Overstay Alert 🚨",
//             `${invitation.guest_name} has exceeded their stay.`,
//             { type: "overstay_alert", invitationId: invitation.id }
//           );
//         } catch (pushErr) {
//           console.error(`Push failed for ${invitation.id}:`, pushErr);
//         }
//       }

//       // Update status immediately after attempting notification
//       await pool.query(
//         "UPDATE invitations SET status = 'overstayed' WHERE id = $1", 
//         [invitation.id]
//       );
//     }));

//     console.log(`[GateMan] Processed ${rows.length} overstays.`);
//   } catch (err) {
//     console.error("Overstay Cron Error:", err);
//   }
// });

// cron.schedule('0 2 * * *', async () => {
//   try {
//     const result = await pool.query(`
//       DELETE FROM invitations 
//       WHERE is_cancelled = true 
//       OR status = 'checked_out'
//       OR (status = 'pending' AND (end_date + end_time) < NOW() - INTERVAL '1 day')
//     `);
//     console.log(`[GateMan Cleanup] Purged ${result.rowCount} old records.`);
//   } catch (err) {
//     console.error("Cleanup Cron Error:", err);
//   }
// });

export default router;