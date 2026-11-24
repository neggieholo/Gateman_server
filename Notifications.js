import express from "express";
import pool from "./db.js";
import {
  isAuth,
  authorizeEstate,
  verifyEstateSubscription,
} from "./middlewares.js";

const router = express.Router();
router.use(isAuth);

router.get(
  "/:estate_id",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    const { id, role } = req.user;
    const { estate_id } = req.params;

    try {
      let targetUserId = id;
      let userTable = "";

      // 1. Determine Target User ID and Table Name
      if (role === "SECURITY") {
        userTable = "security_users";
      } else if (role === "TENANT") {
        userTable = "tenant_users";
      } else if (role === "ADMIN") {
        userTable = "estate_admin_users";

        // Fetch the root admin's ID for this estate
        const rootAdminResult = await pool.query(
          `SELECT eau.id 
           FROM estate_admin_users eau
           JOIN estates e ON e.root_admin_email = eau.email
           WHERE e.id = $1 
           LIMIT 1`,
          [estate_id],
        );

        if (rootAdminResult.rows.length > 0) {
          targetUserId = rootAdminResult.rows[0].id;
        }
      } else {
        return res
          .status(400)
          .json({ error: "Invalid user role for notifications" });
      }

      // 2. Fetch Notifications (Uses targetUserId so all estate admins see root admin notifications)
      const notifs = await pool.query(
        `SELECT * FROM notifications 
         WHERE estate_id = $1 
         AND (user_id = $2 OR (recipient_role = $3 AND user_id IS NULL))
         AND is_deleted = FALSE
         ORDER BY created_at DESC LIMIT 50`,
        [estate_id, targetUserId, role.toLowerCase()],
      );

      // 3. Fetch 'lastReadAt' timestamp for the user/admin
      const userRow = await pool.query(
        `SELECT last_notification_read_at FROM ${userTable} WHERE id = $1`,
        [id],
      );

      res.json({
        success: true,
        list: notifs.rows,
        lastReadAt: userRow.rows[0]?.last_notification_read_at || null,
      });
    } catch (err) {
      console.error("Notification Fetch Error:", err);
      res.status(500).json({ error: "Database error" });
    }
  },
);

// Marking as read is now just one row update
router.put("/read-all", async (req, res) => {
  try {
    const { id, role } = req.user;

    const tableMap = {
      admin: "estate_admin_users",
      tenant: "tenant_users",
      security: "security_users",
    };

    const userRole = role?.toLowerCase();
    const tableName = tableMap[userRole];

    if (!tableName) {
      return res
        .status(400)
        .json({ error: "Invalid user role for this action" });
    }

    // ✅ Fix 2: Execute update query safely
    const updateRes = await pool.query(
      `UPDATE ${tableName} SET last_notification_read_at = NOW() WHERE id = $1 RETURNING last_notification_read_at`,
      [id],
    );

    return res.json({
      success: true,
      message: "All notifications marked as read",
      lastReadAt: updateRes.rows[0]?.last_notification_read_at,
    });
  } catch (err) {
    console.error("Database Error (read-all):", err);
    return res
      .status(500)
      .json({ success: false, error: "Failed to update read status" });
  }
});

router.delete(
  "/delete-all",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    const { id, role, estate_id } = req.user;
    const userRole = role?.toLowerCase();

    try {
      let targetUserId = id;

      // If the user is an admin, resolve targetUserId to the estate's root admin ID
      if (userRole === "admin") {
        const rootAdminResult = await pool.query(
          `SELECT eau.id 
           FROM estate_admin_users eau
           JOIN estates e ON e.root_admin_email = eau.email
           WHERE e.id = $1 
           LIMIT 1`,
          [estate_id],
        );

        if (rootAdminResult.rows.length > 0) {
          targetUserId = rootAdminResult.rows[0].id;
        }
      }

      await pool.query(
        `UPDATE notifications 
         SET is_deleted = TRUE 
         WHERE estate_id = $1 
         AND user_id = $2 
         AND recipient_role = $3`,
        [estate_id, targetUserId, userRole],
      );

      res.json({ success: true, message: "All notifications cleared" });
    } catch (err) {
      console.error("Delete All Error:", err);
      res.status(500).json({ error: "Failed to clear notifications" });
    }
  },
);

router.delete("/:id", authorizeEstate, async (req, res) => {
  const { id: userId, role, estate_id } = req.user;
  const notificationId = req.params.id;
  const userRole = role?.toLowerCase();

  try {
    let targetUserId = userId;

    // If the requesting user is an admin, resolve targetUserId to the estate's root admin ID
    if (userRole === "admin") {
      const rootAdminResult = await pool.query(
        `SELECT eau.id 
         FROM estate_admin_users eau
         JOIN estates e ON e.root_admin_email = eau.email
         WHERE e.id = $1 
         LIMIT 1`,
        [estate_id],
      );

      if (rootAdminResult.rows.length > 0) {
        targetUserId = rootAdminResult.rows[0].id;
      }
    }

    const result = await pool.query(
      `UPDATE notifications 
       SET is_deleted = TRUE 
       WHERE id = $1 
       AND estate_id = $2
       AND (user_id = $3 OR (recipient_role = $4 AND user_id IS NULL))
       RETURNING *`,
      [notificationId, estate_id, targetUserId, userRole],
    );

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Notification not found or unauthorized",
      });
    }

    res.json({ success: true, message: "Notification deleted" });
  } catch (err) {
    console.error("Single Notification Delete Error:", err);
    res.status(500).json({ error: "Database error" });
  }
});

export default router;
