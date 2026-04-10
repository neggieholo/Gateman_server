import express from "express";
import pool from "./db.js";
import { isAuth, broadcastDirectNotification } from "./middlewares.js";

const router = express.Router();

// --- 1. GET POSTS (BY CATEGORY & ESTATE) ---
// router.get("/posts", isAuth, async (req, res) => {
//   const { estate_id, category } = req.query;
//   const user_id = req.user.id;

//   try {
//     const query = `
//       SELECT p.*, 
//       EXISTS (SELECT 1 FROM likes l WHERE l.post_id = p.id AND l.user_id = $3) AS has_liked
//       FROM posts p
//       WHERE p.estate_id = $1 AND p.category = $2
//       ORDER BY p.created_at DESC;
//     `;
//     const { rows } = await pool.query(query, [estate_id, category, user_id]);
//     res.json(rows);
//   } catch (err) {
//     console.error(err);
//     res.status(500).json({ error: "Failed to fetch posts" });
//   }
// });
router.get("/posts", isAuth, async (req, res) => {
  const { estate_id} = req.query;
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
});

// --- 2. CREATE A POST ---
router.post("/posts", isAuth, async (req, res) => {
  const { estate_id, author_name, author_role, title, content, category, image_url, thumbnail_url } = req.body;
  const  author_id = req.user.id
  console.log("Post created:", req.body)
  try {
    const query = `
      INSERT INTO posts (estate_id, author_id, author_name, author_role, title, content, category, image_url, thumbnail_url)
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING *;
    `;
    const { rows } = await pool.query(query, [estate_id, author_id, author_name, author_role, title, content, category, image_url, thumbnail_url]);
    res.status(201).json(rows[0]);
  } catch (err) {
    res.status(500).json({ error: "Post creation failed" });
  }
});

// --- 3. LIKE / UNLIKE A POST (Transaction) ---
router.post("/like", isAuth, async (req, res) => {
  const { post_id } = req.body;
  const user_id = req.user.id;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Check if like exists
    const checkLike = await client.query("SELECT 1 FROM likes WHERE post_id = $1 AND user_id = $2", [post_id, user_id]);

    if (checkLike.rows.length > 0) {
      // Unlike
      await client.query("DELETE FROM likes WHERE post_id = $1 AND user_id = $2", [post_id, user_id]);
      await client.query("UPDATE posts SET likes_count = likes_count - 1 WHERE id = $1", [post_id]);
    } else {
      // Like
      await client.query("INSERT INTO likes (post_id, user_id) VALUES ($1, $2)", [post_id, user_id]);
      await client.query("UPDATE posts SET likes_count = likes_count + 1 WHERE id = $1", [post_id]);
    }

    await client.query("COMMIT");
    res.json({ success: true });
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Like action failed" });
  } finally {
    client.release();
  }
});

// --- 8. GET LIKES FOR A POST ---
router.get("/likes/:post_id", isAuth, async (req, res) => {
  console.log("Fetching likes for post_id:", req.params.post_id);
  const { post_id } = req.params;

  try {
    const query = `
      SELECT l.user_id, l.created_at, u.name as author_name 
      FROM likes l
      JOIN tenant_users u ON l.user_id = u.id
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
router.post("/comments", isAuth, async (req, res) => {
  const { post_id, author_name, content } = req.body;
  const user_id = req.user.id;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // Insert the comment
    const commentQuery = `
      INSERT INTO comments (post_id, user_id, author_name, content)
      VALUES ($1, $2, $3, $4) RETURNING *;
    `;
    const commentResult = await client.query(commentQuery, [post_id, user_id, author_name, content]);

    // Update the count on the post record
    await client.query("UPDATE posts SET comments_count = comments_count + 1 WHERE id = $1", [post_id]);

    await client.query("COMMIT");
    res.status(201).json(commentResult.rows[0]);
  } catch (err) {
    await client.query("ROLLBACK");
    res.status(500).json({ error: "Comment failed" });
  } finally {
    client.release();
  }
});

// --- 5. GET COMMENTS FOR A POST ---
router.get("/comments/:post_id", isAuth, async (req, res) => {
  try {
    const { rows } = await pool.query("SELECT * FROM comments WHERE post_id = $1 ORDER BY created_at ASC", [req.params.post_id]);
    res.json(rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch comments" });
  }
});

// --- 6. DELETE A POST ---
router.delete("/posts/:id", isAuth, async (req, res) => {
  const post_id = req.params.id;
  const user_id = req.user.id;

  try {
    const checkPost = await pool.query(
      "SELECT author_id FROM posts WHERE id = $1",
      [post_id]
    );

    if (checkPost.rows.length === 0) {
      return res.status(404).json({ error: "Post not found" });
    }

    if (checkPost.rows[0].author_id !== user_id) {
      return res.status(403).json({ error: "Unauthorized to delete this post" });
    }

    await pool.query("DELETE FROM posts WHERE id = $1", [post_id]);

    res.json({ success: true, message: "Post deleted successfully" });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to delete post" });
  }
});

// --- 7. DELETE A COMMENT (Transaction) ---
router.delete("/comments/:id", isAuth, async (req, res) => {
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
    await client.query("UPDATE posts SET comments_count = comments_count - 1 WHERE id = $1", [post_id]);

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
  isAuth,
  broadcastDirectNotification,
);

export default router;