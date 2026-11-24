import express from "express";
import pool from "./db.js";
import {
  isAuth,
  ensureAdmin,
  verifyPermission,
  authorizeEstate,
  verifyPlanModule,
  verifyEstateSubscription,
} from "./middlewares.js";
import { io } from "./server.js";
import { sendPushNotification } from "./invitations.js";
import { createAppAuditLog } from "./helpers.js";

const router = express.Router();

router.use(isAuth);

router.get(
  "/posts",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("community"),
  async (req, res) => {
    console.log("Fetching posts for estate_id:", req.query.estate_id);
    const { estate_id } = req.query;
    const user_id = req.user.id;

    try {
      const query = `
      SELECT p.*, 
      EXISTS (SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = $2) AS has_liked
      FROM posts p
      WHERE p.estate_id = $1 AND p.is_archived = false
      ORDER BY p.created_at DESC;
    `;
      const { rows } = await pool.query(query, [estate_id, user_id]);
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to fetch posts" });
    }
  },
);

router.get(
  "/admin-posts",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("community"),
  verifyPermission("view_community_posts", "community_management"),
  async (req, res) => {
    console.log("Fetching posts for estate_id:", req.query.estate_id);
    const { estate_id } = req.query;
    const user_id = req.user.id;

    try {
      const query = `
      SELECT p.*, 
      EXISTS (SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = $2) AS has_liked
      FROM posts p
      WHERE p.estate_id = $1
      ORDER BY p.created_at DESC;
    `;
      const { rows } = await pool.query(query, [estate_id, user_id]);
      res.json(rows);
    } catch (err) {
      console.error(err);
      res.status(500).json({ error: "Failed to fetch posts" });
    }
  },
);

// --- 2. CREATE A POST ---
router.post(
  "/posts",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("community"),
  async (req, res) => {
    const {
      author_name,
      author_role,
      title,
      content,
      category,
      image_url,
      thumbnail_url,
      send_push,
      estate_id,
    } = req.body;

    const author_id = req.user.id;
    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      const postQuery = `
      INSERT INTO posts (estate_id, author_id, author_name, author_role, title, content, category, image_url, thumbnail_url)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *;
    `;
      const postResult = await client.query(postQuery, [
        estate_id,
        author_id,
        author_name,
        author_role,
        title,
        content,
        category,
        image_url,
        thumbnail_url,
      ]);
      const newPost = postResult.rows[0];

      // Track broadcast indicator context for audit logging
      let pushDispatchedCount = 0;

      if (author_role === "admin" && send_push) {
        const { rows: residents } = await client.query(
          "SELECT id, push_token FROM tenant_users WHERE $1::uuid = ANY(estate_ids)",
          [estate_id],
        );

        pushDispatchedCount = residents.length;

        for (const resident of residents) {
          const resDb = await client.query(
            `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'tenant', $3, $4, 'general') RETURNING *`,
            [estate_id, resident.id, title, content],
          );

          const residentNotif = resDb.rows[0];

          io.to(`user_${resident.id}`).emit("new_notification", residentNotif);

          if (resident.push_token) {
            sendPushNotification(resident.push_token, title, content, {
              type: "general",
              post_id: newPost.id,
            });
          }
        }
      }

      await client.query("COMMIT");

      // 1. Respond to the client instantly
      res.status(201).json(newPost);

      // 3. Track operational trail asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "POST_CREATED",
        target_resource: "posts",
        target_id: newPost.id,
        description: `${author_role === "admin" ? "Admin" : "Resident"} published a new post: "${title}".${
          pushDispatchedCount > 0
            ? ` Broadcasted push alerts to ${pushDispatchedCount} residents.`
            : ""
        }`,
        state_before: null,
        state_after: newPost,
        urgency: author_role === "admin" && send_push ? "MEDIUM" : "INFO",
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Post creation/push error:", err);
      res.status(500).json({ error: "Post creation failed" });
    } finally {
      client.release();
    }
  },
);

// --- 3. LIKE / UNLIKE A POST (Transaction) ---
router.post("/like", async (req, res) => {
  const { post_id } = req.body;
  const user_id = req.user.id;

  const user_type =
    req.user.role.toLowerCase() === "admin" ? "admin" : "tenant";

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const checkLike = await client.query(
      "SELECT 1 FROM likes WHERE post_id = $1 AND user_id = $2",
      [post_id, user_id],
    );

    if (checkLike.rows.length > 0) {
      await client.query(
        "DELETE FROM likes WHERE post_id = $1 AND user_id = $2",
        [post_id, user_id],
      );
      await client.query(
        "UPDATE posts SET likes_count = GREATEST(0, likes_count - 1) WHERE id = $1",
        [post_id],
      );
    } else {
      await client.query(
        "INSERT INTO likes (post_id, user_id, user_type) VALUES ($1, $2, $3)",
        [post_id, user_id, user_type],
      );
      await client.query(
        "UPDATE posts SET likes_count = likes_count + 1 WHERE id = $1",
        [post_id],
      );
    }

    await client.query("COMMIT");
    res.json({
      success: true,
      action: checkLike.rows.length > 0 ? "unliked" : "liked",
    });
  } catch (err) {
    if (client) await client.query("ROLLBACK");
    console.error("Like Error:", err);
    res.status(500).json({ error: "Like action failed" });
  } finally {
    client.release();
  }
});

//---GET LIKES---
router.get("/likes/:post_id", async (req, res) => {
  const { post_id } = req.params;

  try {
    const query = `
      SELECT 
        l.user_id, 
        l.user_type,
        l.created_at, 
        CASE 
          WHEN l.user_type = 'admin' THEN 'ADMIN'
          ELSE u.name 
        END as author_name
      FROM likes l
      LEFT JOIN tenant_users u ON l.user_id = u.id AND l.user_type = 'tenant'
      WHERE l.post_id = $1
      ORDER BY l.created_at DESC;
    `;

    const { rows } = await pool.query(query, [post_id]);
    res.json(rows);
  } catch (err) {
    console.error("Error fetching likes:", err);
    res.status(500).json({ error: "Failed to fetch likes" });
  }
});

// --- 4. ADD A COMMENT (Transaction) ---
router.post("/comments", async (req, res) => {
  const { post_id, content } = req.body;
  const user_id = req.user.id;

  // Determine type and name server-side
  const is_admin = req.user.role.toLowerCase() === "admin";
  const user_type = is_admin ? "admin" : "tenant";

  const client = await pool.connect();

  try {
    await client.query("BEGIN");
    const author_display = is_admin ? "ADMIN" : req.user.name;

    const commentQuery = `
      INSERT INTO comments (post_id, user_id, user_type, author_name, content)
      VALUES ($1, $2, $3, $4, $5) RETURNING *;
    `;
    const commentResult = await client.query(commentQuery, [
      post_id,
      user_id,
      user_type,
      author_display,
      content,
    ]);

    await client.query(
      "UPDATE posts SET comments_count = comments_count + 1 WHERE id = $1",
      [post_id],
    );

    await client.query("COMMIT");
    res.status(201).json(commentResult.rows[0]);
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Comment failed" });
  } finally {
    client.release();
  }
});

// --- 5. GET COMMENTS FOR A POST ---
router.get("/comments/:post_id", async (req, res) => {
  try {
    const query = `
      SELECT 
        c.id,
        c.post_id,
        c.user_id,    
        c.user_type,       
        c.content,
        c.created_at,
        CASE 
          WHEN c.user_type = 'admin' THEN 'ADMIN'
          ELSE u.name 
        END as author_name
      FROM comments c
      LEFT JOIN tenant_users u ON c.user_id = u.id AND c.user_type = 'tenant'
      WHERE c.post_id = $1
      ORDER BY c.created_at ASC;
    `;

    const { rows } = await pool.query(query, [req.params.post_id]);
    res.json(rows);
  } catch (err) {
    console.error("Fetch Comments Error:", err);
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// --- 6. DELETE A POST ---
router.delete("/posts/:id", async (req, res) => {
  const post_id = req.params.id;
  const user_id = req.user.id;

  try {
    // 🧠 Grab the entire record state before deletion for our trail
    const checkPost = await pool.query("SELECT * FROM posts WHERE id = $1", [
      post_id,
    ]);

    if (checkPost.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    const postData = checkPost.rows[0];

    if (postData.author_id !== user_id) {
      return res
        .status(403)
        .json({ error: "Unauthorized to delete this post" });
    }

    // Perform the hard delete
    await pool.query("DELETE FROM posts WHERE id = $1", [post_id]);

    // 1. Respond to client instantly
    res.json({ success: true, message: "Post deleted successfully" });

    // 3. Track footprint asynchronously
    await createAppAuditLog(req, {
      estate_id: postData.estate_id || req.user.estate_id || null,
      action_type: "POST_DELETED",
      target_resource: "posts",
      target_id: post_id,
      description: `Deleted post with title: "${postData.title}".`,
      state_before: postData,
      state_after: null,
      urgency: "INFO",
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete post" });
  }
});

// --- 7. DELETE A COMMENT (Transaction) ---
router.delete("/comments/:id", async (req, res) => {
  const comment_id = req.params.id;
  const user_id = req.user.id;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1. Get the post_id and author_id before deleting
    const checkQuery = "SELECT post_id, user_id FROM comments WHERE id = $1";
    const checkResult = await client.query(checkQuery, [comment_id]);

    if (checkResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Comment not found" });
    }

    const { post_id, user_id: author_id } = checkResult.rows[0];

    // 2. Check ownership
    if (author_id !== user_id) {
      await client.query("ROLLBACK");
      return res.status(403).json({ error: "Unauthorized" });
    }

    // 3. Delete the comment
    await client.query("DELETE FROM comments WHERE id = $1", [comment_id]);

    // 4. Decrement the count on the post
    await client.query(
      "UPDATE posts SET comments_count = comments_count - 1 WHERE id = $1",
      [post_id],
    );

    await client.query("COMMIT");
    res.json({ success: true, message: "Comment deleted" });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error(err);
    res.status(500).json({ error: "Failed to delete comment" });
  } finally {
    client.release();
  }
});

router.post(
  "/send-direct-notification",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("community"),
  verifyPermission("send_notifications", "notifications_management"),
  async (req, res) => {
    const { title, message, targets, type, estate_id } = req.body;
    const validType = type || "update";
    const client = await pool.connect();

    try {
      // Keep exact counters of targeted users for clean audit summaries
      const results = { residentsSent: 0, securitySent: 0 };
      let totalResidentsTargeted = 0;
      let totalSecurityTargeted = 0;

      // 1. TARGET RESIDENTS
      if (targets.residents) {
        const { rows: residents } = await client.query(
          "SELECT id, push_token FROM tenant_users WHERE $1 = ANY(estate_ids)",
          [estate_id],
        );

        totalResidentsTargeted = residents.length;

        for (const resident of residents) {
          // Save to DB
          const resDb = await client.query(
            `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
          VALUES ($1, $2, 'tenant', $3, $4, $5) RETURNING *`,
            [estate_id, resident.id, title, message, validType],
          );

          const residentNotif = resDb.rows[0];

          io.to(`user_${resident.id}`).emit("new_notification", residentNotif);

          // Push Notification
          if (resident.push_token) {
            sendPushNotification(resident.push_token, title, message, {
              type: "notification",
              subtype: validType,
            });
            results.residentsSent++;
          }
        }
      }

      // 2. TARGET SECURITY
      if (targets.security) {
        const { rows: guards } = await client.query(
          "SELECT id, push_token FROM security_users WHERE estate_id = $1",
          [estate_id],
        );

        totalSecurityTargeted = guards.length;

        for (const guard of guards) {
          const resDb = await client.query(
            `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
          VALUES ($1, $2, 'security', $3, $4, $5) RETURNING *`,
            [estate_id, guard.id, title, message, validType],
          );

          const guardNotif = resDb.rows[0];

          io.to(`user_${guard.id}`).emit("new_notification", guardNotif);

          if (guard.push_token) {
            sendPushNotification(guard.push_token, title, message, {
              type: "notification",
              subtype: validType,
            });
            results.securitySent++;
          }
        }
      }

      // 1. Respond instantly to front-end execution thread
      res.status(200).json({ success: true, results });

      // 2. Derive dynamic naming properties matching your structural style
      const alertNamespace = validType.toUpperCase().trim();
      const dynamicActionType = `DIRECT_${alertNamespace}_NOTIFICATION_DISPATCHED`;
      const targetResource = "notifications";

      // 3. Document the bulk execution blueprint asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: dynamicActionType,
        target_resource: targetResource,
        target_id: estate_id,
        description: `Admin broadcasted a manual direct notification: "${title}". Targets: [Residents: ${totalResidentsTargeted}, Security: ${totalSecurityTargeted}].`,
        state_before: null,
        state_after: {
          title,
          message,
          type: validType,
          scope: targets,
          delivery_metrics: {
            residents_push_delivered: results.residentsSent,
            security_push_delivered: results.securitySent,
          },
        },
        // 💡 Mark as HIGH if it's an emergency alert blasted out, otherwise MEDIUM
        urgency: validType.toLowerCase() === "emergency" ? "HIGH" : "MEDIUM",
      });
    } catch (error) {
      console.error("Broadcast Error:", error);
      res
        .status(500)
        .json({ success: false, error: "Failed to dispatch notifications" });
    } finally {
      client.release();
    }
  },
);

router.patch(
  "/posts/:id/seen",
  ensureAdmin,
  verifyPermission("view_community_posts", "community_management"),
  async (req, res) => {
    const { id } = req.params;
    try {
      await pool.query("UPDATE posts SET admin_seen = TRUE WHERE id = $1", [
        id,
      ]);
      res.json({ success: true });
    } catch (err) {
      res.status(500).json({ error: "Failed to update seen status" });
    }
  },
);

router.patch(
  "/posts/:postId/archive",
  ensureAdmin,
  verifyPermission("moderate_community_posts", "community_management"),
  async (req, res) => {
    const { postId } = req.params;

    try {
      const query = `
      UPDATE posts 
      SET is_archived = true 
      WHERE id = $1 
      RETURNING *;
    `;
      const { rows } = await pool.query(query, [postId]);

      if (rows.length === 0) {
        return res.status(404).json({ error: "Post record target not found." });
      }

      res.json({
        success: true,
        message: "Post successfully archived",
        post: rows[0],
      });
    } catch (err) {
      console.error("Archive API Error:", err);
      res.status(500).json({ error: "Internal server error archiving post." });
    }
  },
);

// POST /resident/update-feed-read
router.post(
  "/update-feed-read",
  isAuth,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("community"),
  async (req, res) => {
    const { id: user_id } = req.user; // Your authenticated user ID
    const { estate_id } = req.body; // Sent from your React Native useEffect
    console.log("Updating feed read for user:", user_id, "estate:", estate_id);

    if (!estate_id) {
      return res
        .status(400)
        .json({ success: false, message: "Missing estate_id" });
    }

    try {
      const updateQuery = `
      UPDATE tenant_users 
      SET last_post_read = jsonb_set(
        COALESCE(last_post_read, '{}'::jsonb), 
        ARRAY[$2],                             -- Target key path (the estate_id string)
        to_jsonb(NOW()::text)                  -- New timestamp value converted to JSONB
      ) 
      WHERE id = $1                            -- Confirmed: matching your 'id' column mapping
      RETURNING last_post_read;
    `;

      const result = await pool.query(updateQuery, [user_id, estate_id]);

      if (result.rowCount === 0) {
        return res.status(404).json({
          success: false,
          message: "Tenant user tracking profile not found",
        });
      }

      res.json({
        success: true,
        last_post_read: result.rows[0].last_post_read,
      });
    } catch (err) {
      console.error("JSONB Metric Sync Error:", err);
      res.status(500).json({ error: "Failed to update feed metrics" });
    }
  },
);

router.get("/get-feed-read", isAuth, async (req, res) => {
  const { id: user_id } = req.user;
  console.log("Fetching feed read markers for user:", user_id);

  try {
    // Select just the last_post_read JSONB column for optimized performance
    const selectQuery = `
      SELECT last_post_read 
      FROM tenant_users 
      WHERE id = $1;
    `;

    const result = await pool.query(selectQuery, [user_id]);

    if (result.rowCount === 0) {
      return res.status(404).json({
        success: false,
        message: "Tenant user profile not found",
      });
    }

    // Default to an empty object if the column is currently NULL in the database
    const last_post_read = result.rows[0].last_post_read || {};

    res.json({
      success: true,
      last_post_read,
    });
  } catch (err) {
    console.error("Fetch JSONB Metric Error:", err);
    res.status(500).json({ error: "Failed to retrieve feed read metrics" });
  }
});

export default router;
