import express from "express";
import pool from "./db.js";
import { isAuth } from "./middlewares.js";
const router = express.Router();


router.get("/", isAuth, async (req, res) => {
  const { id, estate_id, role } = req.user;
  
  try {
    // 1. Get the notifications (This part remains the same)
    const notifs = await pool.query(`
      SELECT * FROM notifications 
      WHERE estate_id = $1 
      AND (user_id = $2 OR (recipient_role = $3 AND user_id IS NULL))
      AND is_deleted = FALSE
      ORDER BY created_at DESC LIMIT 50`, 
      [estate_id, id, role.toLowerCase()]
    );

    // 2. Determine which table to check for the 'lastReadAt' timestamp
    // We sanitize the role check to ensure we hit the right table
    let userTable = "";
    if (role === 'SECURITY') {
      userTable = "security_users";
    } else if (role === 'TENANT') {
      userTable = "tenant_users";
    } else {
      return res.status(400).json({ error: "Invalid user role for notifications" });
    }

    // 3. Get the user's last read timestamp from the specific table
    const userRow = await pool.query(
      `SELECT last_notification_read_at FROM ${userTable} WHERE id = $1`, 
      [id]
    );

    res.json({ 
      success: true, 
      list: notifs.rows, 
      lastReadAt: userRow.rows[0]?.last_notification_read_at || null
    });

  } catch (err) {
    console.error("Notification Fetch Error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

// Marking as read is now just one row update
router.put("/read-all", isAuth, async (req, res) => {
  const { id, role } = req.user;

  // 1. Map roles to their respective tables
  const tableMap = {
    tenant: "tenant_users",
    security: "security_users"
    // admin: "admin_users" // Optional, if admins have notifications too
  };

  const tableName = tableMap[role?.toLowerCase()];

  if (!tableName) {
    return res.status(400).json({ error: "Invalid user role for this action" });
  }

  try {
    await pool.query(
      `UPDATE ${tableName} SET last_notification_read_at = NOW() WHERE id = $1`, 
      [id]
    );
    
    res.json({ success: true, message: "All notifications marked as read" });
  } catch (err) {
    console.error("Database Error:", err);
    res.status(500).json({ error: "Failed to update read status" });
  }
});


router.delete("/:id", isAuth, async (req, res) => {
  const { id: userId, role } = req.user;
  const notificationId = req.params.id;

  try {
    const result = await pool.query(
      `UPDATE notifications 
       SET is_deleted = TRUE 
       WHERE id = $1 
       AND (user_id = $2 OR (recipient_role = $3 AND user_id IS NULL))
       RETURNING *`,
      [notificationId, userId, role]
    );

    if (result.rowCount === 0) {
      return res.status(404).json({ success: false, message: "Notification not found" });
    }

    res.json({ success: true, message: "Notification deleted" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Database error" });
  }
});

export default router;