import express from "express";
import pool from "./db.js";
import { isAuth, verifyPermission, isSuperAdmin } from "./middlewares.js";

const router = express.Router();
router.use(isAuth);
router.use(isSuperAdmin);

router.get(
  "/",
  verifyPermission("read_notifications", "notifications_management"),
  async (req, res) => {
    const { id: superAdminId, role } = req.user;

    try {
      // 1. Fetch admin details with COALESCE fallback for new users
      const adminResult = await pool.query(
        `SELECT 
           sa.id, 
           COALESCE(sanr.last_read_at, sa.created_at) AS last_read_at
         FROM super_admins sa
         LEFT JOIN super_admin_notification_reads sanr ON sa.id = sanr.super_admin_id
         WHERE sa.id = $1`,
        [superAdminId],
      );

      if (adminResult.rows.length === 0) {
        return res.status(404).json({
          success: false,
          error: "Super admin account profile not found.",
        });
      }

      const lastReadAt = adminResult.rows[0].last_read_at;

      // 2. Fetch global notifications intended for super admins
      const notifs = await pool.query(
        `SELECT * FROM notifications 
         WHERE recipient_role = $1
           AND is_deleted = FALSE
         ORDER BY created_at DESC 
         LIMIT 50`,
        [role.toLowerCase()],
      );

      return res.json({
        success: true,
        list: notifs.rows,
        lastReadAt,
      });
    } catch (err) {
      console.error("Super Admin Notification Fetch Error:", err);
      return res.status(500).json({ error: "Database error" });
    }
  },
);

// Marking as read is now just one row update
router.put(
  "/read-all",
  verifyPermission("read_notifications", "notifications_management"),
  async (req, res) => {
    const { id: superAdminId, role } = req.user;

    // Reject non-super-admin requests
    if (role?.toLowerCase() !== "super_admin") {
      return res.status(403).json({
        success: false,
        error: "Forbidden: This endpoint is strictly for Super Admins.",
      });
    }

    try {
      // UPSERT: Create row if first time, or update timestamp if row already exists
      const result = await pool.query(
        `INSERT INTO super_admin_notification_reads (super_admin_id, last_read_at)
         VALUES ($1, NOW())
         ON CONFLICT (super_admin_id) 
         DO UPDATE SET last_read_at = EXCLUDED.last_read_at
         RETURNING last_read_at`,
        [superAdminId],
      );

      return res.json({
        success: true,
        message: "All super admin notifications marked as read.",
        lastReadAt: result.rows[0].last_read_at,
      });
    } catch (err) {
      console.error("Super Admin Read-All Error:", err);
      return res.status(500).json({ error: "Failed to update read status" });
    }
  },
);

router.delete(
  "/delete-all",
  verifyPermission("delete_notifications", "notifications_management"),
  async (req, res) => {
    const { role } = req.user;

    // Enforce strict Super Admin access control
    if (role?.toLowerCase() !== "super_admin") {
      return res.status(403).json({
        success: false,
        error: "Forbidden: This endpoint is strictly for Super Admins.",
      });
    }

    try {
      // Soft delete all global super admin notifications
      await pool.query(
        `UPDATE notifications 
         SET is_deleted = TRUE 
         WHERE recipient_role = 'super_admin' 
           AND is_deleted = FALSE`,
      );

      return res.json({
        success: true,
        message: "All super admin notifications have been cleared.",
      });
    } catch (err) {
      console.error("Super Admin Clear-All Error:", err);
      return res.status(500).json({ error: "Failed to clear notifications" });
    }
  },
);

router.delete(
  "/:id",
  verifyPermission("delete_notifications", "notifications_management"),
  async (req, res) => {
    const { role } = req.user;
    const notificationId = req.params.id;

    // Strict Super Admin check
    if (role?.toLowerCase() !== "super_admin") {
      return res.status(403).json({
        success: false,
        error: "Forbidden: This endpoint is strictly for Super Admins.",
      });
    }

    try {
      // Soft-delete the single global notification by ID
      const result = await pool.query(
        `UPDATE notifications 
         SET is_deleted = TRUE 
         WHERE id = $1 
           AND recipient_role = 'super_admin' 
           AND is_deleted = FALSE
         RETURNING *`,
        [notificationId],
      );

      if (result.rowCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Notification not found or already deleted.",
        });
      }

      return res.json({
        success: true,
        message: "Notification deleted successfully.",
      });
    } catch (err) {
      console.error("Super Admin Single Notification Delete Error:", err);
      return res.status(500).json({ error: "Database error" });
    }
  },
);

export default router;
