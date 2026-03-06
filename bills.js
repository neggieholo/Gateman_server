import express from "express";
import pool from "./db.js";

const router = express.Router();

/**
 * POST /bills/add
 * Body: {
 *   name: string,
 *   description?: string,
 *   amount: number,
 *   billing_cycle: 'monthly' | 'one_time',
 *   due_day?: number
 * }
 * estate_id comes from req.user.estate_id
 */
router.post("/add", async (req, res) => {
  try {
    const user = req.user;
    if (!user || !user.estate_id) {
      return res.status(403).json({ error: "Unauthorized or missing estate info" });
    }

    const estate_id = user.estate_id;
    const { name, description, amount, billing_cycle, due_day } = req.body;

    if (!name || amount === undefined || !billing_cycle) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    if (billing_cycle === "monthly" && (!due_day || due_day < 1 || due_day > 28)) {
      return res.status(400).json({ error: "Invalid or missing due_day for monthly bill" });
    }

    const result = await pool.query(
      `INSERT INTO billable_items
        (estate_id, name, description, amount, billing_cycle, due_day)
       VALUES ($1,$2,$3,$4,$5,$6)
       RETURNING *`,
      [estate_id, name, description || null, amount, billing_cycle, due_day || null]
    );

    return res.status(201).json({ success: true, bill: result.rows[0] });
  } catch (error) {
    console.error("Error creating bill:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * GET /bills
 * Fetch all bills for the estate
 */
router.get("/", async (req, res) => {
  try {
    const user = req.user;
    if (!user || !user.estate_id) {
      return res.status(403).json({ error: "Unauthorized or missing estate info" });
    }

    const estate_id = user.estate_id;

    const result = await pool.query(
      `SELECT id, name, description, amount, billing_cycle, due_day, is_active, created_at, updated_at
       FROM billable_items
       WHERE estate_id = $1
       ORDER BY created_at DESC`,
      [estate_id]
    );

    return res.status(200).json({ success: true, bills: result.rows });
  } catch (error) {
    console.error("Error fetching bills:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * PUT /bills/:id
 * Body: Partial bill fields to update
 */
router.put("/:id", async (req, res) => {
  try {
    const user = req.user;
    if (!user || !user.estate_id) {
      return res.status(403).json({ error: "Unauthorized or missing estate info" });
    }

    const { id } = req.params;
    const { name, description, amount, billing_cycle, due_day, is_active } = req.body;

    const fields = [];
    const values = [];
    let idx = 1;

    if (name !== undefined) { fields.push(`name = $${idx++}`); values.push(name); }
    if (description !== undefined) { fields.push(`description = $${idx++}`); values.push(description); }
    if (amount !== undefined) { fields.push(`amount = $${idx++}`); values.push(amount); }
    if (billing_cycle !== undefined) { fields.push(`billing_cycle = $${idx++}`); values.push(billing_cycle); }
    if (due_day !== undefined) { fields.push(`due_day = $${idx++}`); values.push(due_day); }
    if (is_active !== undefined) { fields.push(`is_active = $${idx++}`); values.push(is_active); }

    if (fields.length === 0) {
      return res.status(400).json({ error: "No fields provided to update" });
    }

    fields.push(`updated_at = NOW()`);

    const query = `
      UPDATE billable_items
      SET ${fields.join(", ")}
      WHERE id = $${idx} AND estate_id = $${idx + 1}
      RETURNING *
    `;
    values.push(id, user.estate_id);

    const result = await pool.query(query, values);

    if (!result.rows.length) {
      return res.status(404).json({ error: "Bill not found or not authorized" });
    }

    return res.status(200).json({ success: true, bill: result.rows[0] });
  } catch (error) {
    console.error("Error updating bill:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * PUT /bills/:id/toggle
 * Toggle is_active field
 */
router.put("/:id/toggle", async (req, res) => {
  try {
    const user = req.user;
    if (!user || !user.estate_id) {
      return res.status(403).json({ error: "Unauthorized or missing estate info" });
    }

    const { id } = req.params;

    const billRes = await pool.query(
      "SELECT is_active FROM billable_items WHERE id=$1 AND estate_id=$2",
      [id, user.estate_id]
    );

    if (!billRes.rows.length) {
      return res.status(404).json({ error: "Bill not found" });
    }

    const newStatus = !billRes.rows[0].is_active;

    const updated = await pool.query(
      "UPDATE billable_items SET is_active=$1, updated_at=NOW() WHERE id=$2 RETURNING *",
      [newStatus, id]
    );

    return res.status(200).json({ success: true, bill: updated.rows[0] });
  } catch (err) {
    console.error("Error toggling bill:", err);
    return res.status(500).json({ error: "Internal server error" });
  }
});

/**
 * DELETE /bills/:id
 */
router.delete("/:id", async (req, res) => {
  try {
    const user = req.user;
    if (!user || !user.estate_id) {
      return res.status(403).json({ error: "Unauthorized or missing estate info" });
    }

    const { id } = req.params;

    const result = await pool.query(
      `DELETE FROM billable_items
       WHERE id = $1 AND estate_id = $2
       RETURNING *`,
      [id, user.estate_id]
    );

    if (!result.rows.length) {
      return res.status(404).json({ error: "Bill not found or not authorized" });
    }

    return res.status(200).json({ success: true, bill: result.rows[0] });
  } catch (error) {
    console.error("Error deleting bill:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

export default router;
