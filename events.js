import express from "express";
import pool from "./db.js";
import { isAuth, ensureAdmin } from "./middlewares.js";
import crypto from "crypto";
import axios from "axios";
import bcrypt from "bcrypt";

const router = express.Router();

// --- 1. CREATE EVENT ---
router.post("/create", isAuth, async (req, res) => {
  const {
    title,
    banner_url,
    description,
    start_date,
    end_date,
    start_time,
    end_time,
    venue_detail,
    expected_guests,
    is_paid,
    ticket_price,
    bank_name,
    bank_code,
    account_number,
  } = req.body;

  const { id, estate_id, subaccount_id: existingSubaccount } = req.user;

  try {
    // Generate a clean 6-character Ref Code (e.g., GT-X92)
    const ref_code = `GT-${crypto.randomBytes(2).toString("hex").toUpperCase()}`;

    // Logic: If paid, trigger Flutterwave Subaccount Creation
    let subaccount_to_use = existingSubaccount;

    if (is_paid && !subaccount_to_use) {
      subaccount_to_use = "FLW_SUB_NEW_999";

      await pool.query(
        "UPDATE tenant_users SET subaccount_id = $1 WHERE id = $2",
        [subaccount_to_use, id],
      );
    }

    const newEvent = await pool.query(
      `INSERT INTO estate_events (
                estate_id, organizer_id, title, banner_url, description, 
                start_date, end_date, start_time, end_time, 
                venue_detail, expected_guests, is_paid, 
                ticket_price, subaccount_id, ref_code, bank_code, bank_name, account_number
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) 
            RETURNING *`,
      [
        estate_id,
        id,
        title,
        banner_url || null,
        description || null,
        start_date,
        end_date,
        start_time,
        end_time,
        venue_detail || null,
        expected_guests || 0,
        is_paid || false,
        ticket_price,
        subaccount_to_use || null,
        ref_code,
        bank_code || null,
        bank_name || null,
        account_number || null,
      ],
    );

    res.status(201).json({
      message: "Event submitted for approval",
      event: newEvent.rows[0],
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Failed to create event" });
  }
});

// --- 2. GET ALL EVENTS (For specific Estate) ---
router.get("/all", ensureAdmin, async (req, res) => {
  const { estate_id } = req.user;
  try {
    const events = await pool.query(
      "SELECT * FROM estate_events WHERE estate_id = $1 ORDER BY start_date ASC",
      [estate_id],
    );
    res.json(events.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// --- 2. GET ALL EVENTS (For specific resident) ---
router.get("/organizer/all", isAuth, async (req, res) => {
  const { id, estate_id } = req.user;
  try {
    const events = await pool.query(
      "SELECT * FROM estate_events WHERE estate_id = $1 AND organizer_id = $2 ORDER BY start_date ASC",
      [estate_id, id],
    );
    res.json(events.rows);
  } catch (err) {
    res.status(500).json({ error: "Failed to fetch events" });
  }
});

// --- 4. DELETE EVENT ---
router.delete("/delete/:id", isAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const check = await pool.query(
      "SELECT organizer_id FROM estate_events WHERE id = $1",
      [id],
    );

    if (check.rows[0]?.organizer_id !== req.user.id) {
      return res
        .status(403)
        .json({ error: "Unauthorized to delete this event" });
    }

    await pool.query("DELETE FROM estate_events WHERE id = $1", [id]);
    res.json({ message: "Event cancelled successfully" });
  } catch (err) {
    res.status(500).json({ error: "Delete failed" });
  }
});

// --- 5. CANCEL RSVP ---
router.delete("/rsvp/cancel/:guest_code", async (req, res) => {
  try {
    const { guest_code } = req.params;
    await pool.query("DELETE FROM event_registrations WHERE guest_code = $1", [
      guest_code,
    ]);
    res.json({ message: "RSVP cancelled" });
  } catch (err) {
    res.status(500).json({ error: "Cancellation failed" });
  }
});

// --- REGISTER / RSVP API ---
router.post("/rsvp", async (req, res) => {
  const { event_id, guest_name, guest_email } = req.body;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    // 1. Fetch event and LOCK row for capacity verification
    const eventResult = await client.query(
      `SELECT is_paid, ticket_price, subaccount_id, expected_guests, registered_number 
       FROM estate_events WHERE id = $1 FOR UPDATE`,
      [event_id],
    );

    if (eventResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Event not found" });
    }

    const event = eventResult.rows[0];

    // 2. Capacity Check
    if (event.registered_number >= event.expected_guests) {
      await client.query("ROLLBACK");
      return res
        .status(400)
        .json({ error: "This event is already at full capacity." });
    }

    // 3. If FREE: Immediate Registration
    if (!event.is_paid) {
      const guest_code = `GUEST-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

      await client.query(
        `INSERT INTO event_registrations (event_id, guest_name, guest_email, guest_code) 
         VALUES ($1, $2, $3, $4)`,
        [event_id, guest_name, guest_email, guest_code],
      );

      // Increment registered number
      await client.query(
        "UPDATE estate_events SET registered_number = registered_number + 1 WHERE id = $1",
        [event_id],
      );

      await client.query("COMMIT");
      return res.status(201).json({
        message: "Registration successful",
        guest_code: guest_code,
      });
    }

    // 4. If PAID: Initialize Paystack Transaction
    const amount = Math.round(parseFloat(event.ticket_price) * 100);
    const reference = `RSVP_${crypto.randomBytes(4).toString("hex")}_${Date.now()}`;

    const paymentData = {
      email: guest_email,
      amount,
      reference,
      subaccount: event.subaccount_id,
      callback_url: "https://your-domain.app/api/events/callback",
      metadata: { event_id, guest_name, guest_email },
    };

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      paymentData,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_KEY}`,
          "Content-Type": "application/json",
        },
      },
    );

    // Store temp info until webhook confirms
    await client.query(
      `INSERT INTO temp_payment_info (tx_ref, name, email, metadata) 
       VALUES ($1, $2, $3, $4)`,
      [reference, guest_name, guest_email, JSON.stringify({ event_id })],
    );

    await client.query("COMMIT");
    res.json({ paymentLink: response.data.data.authorization_url });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("RSVP Error:", err.message);
    res.status(500).json({ error: "RSVP initialization failed" });
  } finally {
    client.release();
  }
});

// --- UPDATED WEBHOOK TO HANDLE BOTH ESTATE REG & EVENT RSVP ---
router.post("/paystack-webhook", async (req, res) => {
  const secret = process.env.PAYSTACK_SECRET_KEY;
  const hash = crypto
    .createHmac("sha512", secret)
    .update(JSON.stringify(req.body))
    .digest("hex");

  if (hash !== req.headers["x-paystack-signature"]) return res.sendStatus(400);

  const event = req.body;
  if (event.event !== "charge.success") return res.sendStatus(200);

  const { reference } = event.data;
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const tempResult = await client.query(
      "SELECT * FROM temp_payment_info WHERE tx_ref = $1",
      [reference],
    );

    if (tempResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.sendStatus(200);
    }

    const temp = tempResult.rows[0];
    const { event_id } = JSON.parse(temp.metadata);
    const guest_code = `GUEST-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

    // 1. Create the final registration record
    await client.query(
      `INSERT INTO event_registrations (event_id, guest_name, guest_email, guest_code) 
       VALUES ($1, $2, $3, $4)`,
      [event_id, temp.name, temp.email, guest_code],
    );

    // 2. Increment the registered number on the event
    await client.query(
      "UPDATE estate_events SET registered_number = registered_number + 1 WHERE id = $1",
      [event_id],
    );

    // 3. Cleanup temp table
    await client.query("DELETE FROM temp_payment_info WHERE tx_ref = $1", [
      reference,
    ]);

    await client.query("COMMIT");
    console.log(`✅ RSVP Confirmed and counter updated for ${temp.email}`);
    res.sendStatus(200);
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Webhook Error:", error);
    res.status(500).send("Internal Server Error");
  } finally {
    client.release();
  }
});

// --- APPROVE EVENT ---
// Access: Only Estate Admin
router.patch("/approve/:event_id", ensureAdmin, async (req, res) => {
  console.log("Approval request received for event ID:", req.body);
  const { event_id } = req.params;
  const { verdict } = req.body;
  const { estate_id } = req.user;

  try {
    // 1. Determine values based on verdict
    const isApprove = verdict === "approve";
    const isReject = verdict === "reject";

    if (!isApprove && !isReject) {
      return res
        .status(400)
        .json({ error: "Invalid verdict. Use 'approve' or 'reject'." });
    }

    // 2. Mutual Exclusion: If approving, set rejected to false (and vice versa)
    // This allows admins to "change their mind" without data conflicts
    const query = `
      UPDATE estate_events 
      SET is_approved = $1, 
          is_rejected = $2 
      WHERE id = $3 AND estate_id = $4 
      RETURNING *`;

    const values = [isApprove, isReject, event_id, estate_id];
    const result = await pool.query(query, values);

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Event not found in your estate." });
    }

    const updatedEvent = result.rows[0];

    res.json({
      success: true,
      message: isApprove
        ? "Event approved successfully!"
        : "Event rejected successfully!",
      event: updatedEvent,
    });
  } catch (err) {
    console.error("Approval error:", err);
    res.status(500).json({ error: "Server error during approval process" });
  }
});

export default router;
