import express from "express";
import pool from "./db.js";
import { isAuth, ensureAdmin } from "./middlewares.js";
import crypto from "crypto";
import axios from "axios";
import bcrypt from "bcrypt";
import { sendEventGuestCode } from "./emailService.js";

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

  const {
    id: organizer_id,
    estate_id,
    subaccount_id: existingSubaccount,
  } = req.user;

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    let subaccount_to_use = existingSubaccount;

    // Placeholder for your Flutterwave subaccount logic
    if (is_paid && !subaccount_to_use) {
      subaccount_to_use = `FLW_SUB_${crypto.randomBytes(3).toString("hex").toUpperCase()}`;
      await client.query(
        "UPDATE tenant_users SET subaccount_id = $1 WHERE id = $2",
        [subaccount_to_use, organizer_id],
      );
    }

    let newEvent;
    let attempts = 0;
    const maxAttempts = 10;

    // --- COLLISION RETRY LOOP ---
    while (attempts < maxAttempts) {
      try {
        const ref_code = `GT-${crypto.randomBytes(2).toString("hex").toUpperCase()}`;

        const insertQuery = `
          INSERT INTO estate_events (
            estate_id, organizer_id, title, banner_url, description, 
            start_date, end_date, start_time, end_time, 
            venue_detail, expected_guests, is_paid, 
            ticket_price, subaccount_id, ref_code, bank_code, bank_name, account_number
          ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18) 
          RETURNING *`;

        const values = [
          estate_id,
          organizer_id,
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
          ticket_price || 0,
          subaccount_to_use || null,
          ref_code,
          bank_code || null,
          bank_name || null,
          account_number || null,
        ];

        const result = await client.query(insertQuery, values);
        newEvent = result.rows[0];
        break; // Success! Exit the loop.
      } catch (err) {
        // Postgres Unique Violation code is 23505
        if (err.code === "23505") {
          attempts++;
          continue; // Try again with a new code
        }
        throw err; // Real error, bail out
      }
    }

    if (!newEvent) {
      throw new Error(
        "Failed to generate a unique reference code after multiple attempts.",
      );
    }

    await client.query("COMMIT");
    res.status(201).json({
      message: "Event submitted for approval",
      event: newEvent,
    });
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("Create Event Error:", err);
    res.status(500).json({ error: "Failed to create event" });
  } finally {
    client.release();
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

// --- 5. GET SINGLE EVENT BY ID (Public RSVP) ---
router.get("/public/:id", async (req, res) => {
  const { id } = req.params;
  console.log("Fetching public event with ref_code:", id);

  try {
    const result = await pool.query(
      `SELECT 
        id, estate_id, title, banner_url, description, 
        start_date, end_date, start_time, end_time, 
        venue_detail, expected_guests, is_paid, 
        ticket_price, ref_code, is_approved
       FROM estate_events 
       WHERE ref_code = $1`,
      [id],
    );

    if (result.rows.length === 0) {
      return res.status(404).json({ error: "Event not found" });
    }

    const event = result.rows[0];

    if (!event.is_approved) {
      return res.status(403).json({
        error: "This event is pending approval and is not yet public.",
      });
    }

    res.json(event);
  } catch (err) {
    console.error("Error fetching public event:", err);
    res.status(500).json({ error: "Internal server error" });
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
      `SELECT id, is_paid, ticket_price, subaccount_id, expected_guests, registered_guests
       FROM estate_events WHERE id = $1 FOR UPDATE`,
      [event_id],
    );

    if (eventResult.rows.length === 0) {
      await client.query("ROLLBACK");
      return res.status(404).json({ error: "Event not found" });
    }

    const eventData = eventResult.rows[0];
    const eventName = eventData.title || "the event";

    // 2. Capacity Check
    if (eventData.registered_guests >= eventData.expected_guests) {
      await client.query("ROLLBACK");
      return res
        .status(400)
        .json({ error: "This event is already at full capacity." });
    }

    // 3. If FREE: Immediate Registration
    if (!eventData.is_paid) {
      const prefix = (eventName || "GateMan")
        .substring(0, 2)
        .toUpperCase()
        .replace(/[^A-Z]/g, "X");

      const randomPart = crypto.randomBytes(4).toString("hex").toUpperCase();

      const guest_code = `${prefix}-${randomPart}`;

      await client.query(
        `INSERT INTO event_registrations (event_id, guest_name, guest_email, guest_code) 
         VALUES ($1, $2, $3, $4)`,
        [event_id, guest_name, guest_email, guest_code],
      );

      await client.query(
        "UPDATE estate_events SET registered_guests = registered_guests + 1 WHERE id = $1",
        [event_id],
      );

      await client.query("COMMIT");

      await sendEventGuestCode(guest_email, guest_name, eventName, guest_code);
      return res
        .status(201)
        .json({ message: "Registration successful", guest_code });
    }

    // 4. If PAID: Initialize Paystack
    const amount = Math.round(parseFloat(eventData.ticket_price) * 100);
    const reference = `RSVP_${crypto.randomBytes(4).toString("hex")}_${Date.now()}`;

    // Note: Storing event_id in metadata for the Paystack dashboard view
    const paymentData = {
      email: guest_email,
      amount,
      reference,
      // subaccount: eventData.subaccount_id,
      callback_url:
        "https://d7e9-129-205-124-247.ngrok-free.app/api/payment/callback",
      metadata: { event_id, guest_name },
    };

    const response = await axios.post(
      "https://api.paystack.co/transaction/initialize",
      paymentData,
      {
        headers: {
          Authorization: `Bearer ${process.env.PAYSTACK_SECRET_TEST_KEY}`,
          "Content-Type": "application/json",
        },
      },
    );

    await client.query(
      `INSERT INTO temp_event_payments (tx_ref, event_id, guest_name, guest_email, metadata) 
      VALUES ($1, $2, $3, $4, $5)`,
      [
        reference,
        event_id,
        guest_name,
        guest_email,
        JSON.stringify({ type: "EVENT_RSVP" }),
      ],
    );

    await client.query("COMMIT");
    res.json({ paymentLink: response.data.data.authorization_url });
  } catch (axiosErr) {
    await client.query("ROLLBACK");
    console.error("RSVP Error:", axiosErr.message);
    res.status(500).json({ error: "RSVP initialization failed" });
  } finally {
    client.release();
  }
});

// --- UPDATED WEBHOOK TO HANDLE BOTH ESTATE REG & EVENT RSVP ---
// router.post("/paystack-webhook", async (req, res) => {
//   const secret = process.env.PAYSTACK_SECRET_TEST_KEY;
//   const hash = crypto
//     .createHmac("sha512", secret)
//     .update(JSON.stringify(req.body))
//     .digest("hex");

//   if (hash !== req.headers["x-paystack-signature"]) return res.sendStatus(400);

//   const payload = req.body;
//   if (payload.event !== "charge.success") return res.sendStatus(200);

//   const { reference } = payload.data;
//   const client = await pool.connect();

//   try {
//     await client.query("BEGIN");

//     const tempResult = await client.query(
//       "SELECT * FROM temp_event_payments WHERE tx_ref = $1",
//       [reference],
//     );

//     if (tempResult.rows.length === 0) {
//       await client.query("ROLLBACK");
//       return res.sendStatus(200);
//     }

//     const temp = tempResult.rows[0];

//     // Safely parse metadata
//     const metadata =
//       typeof temp.metadata === "string"
//         ? JSON.parse(temp.metadata)
//         : temp.metadata;

//     if (metadata?.type === "EVENT_RSVP") {
//       const guest_code = `GUEST-${crypto.randomBytes(3).toString("hex").toUpperCase()}`;

//       // 1. Finalize Registration
//       await client.query(
//         `INSERT INTO event_registrations (event_id, guest_name, guest_email, guest_code, tx_ref)
//          VALUES ($1, $2, $3, $4, $5)`,
//         [temp.event_id, temp.guest_name, temp.guest_email, guest_code, reference],
//       );

//       // 2. Increment Counter
//       await client.query(
//         "UPDATE estate_events SET registered_guests = registered_guests + 1 WHERE id = $1",
//         [metadata.event_id],
//       );

//       console.log(`✅ RSVP Confirmed for ${temp.email}`);
//     }

//     // Cleanup
//     await client.query("DELETE FROM temp_event_payments WHERE tx_ref = $1", [
//       reference,
//     ]);

//     await client.query("COMMIT");
//     res.sendStatus(200);
//   } catch (error) {
//     await client.query("ROLLBACK");
//     console.error("Webhook Error:", error);
//     res.status(500).send("Internal Server Error");
//   } finally {
//     client.release();
//   }
// });

// router.get("/callback", async (req, res) => {
//   const { reference } = req.query;

//   try {
//     const response = await axios.get(
//       `https://api.paystack.co/transaction/verify/${reference}`,
//       {
//         headers: {
//           Authorization: `Bearer ${process.env.PAYSTACK_SECRET_TEST_KEY}`,
//         },
//       },
//     );

//     if (response.data.data.status === "success") {
//       // Look for the registration using the reference we just saved
//       const regResult = await pool.query(
//         "SELECT guest_code FROM event_registrations WHERE tx_ref = $1",
//         [reference],
//       );

//       if (regResult.rows.length > 0) {
//         // SUCCESS: Webhook already finished
//         const code = regResult.rows[0].guest_code;
//         return res.redirect(
//           `http://localhost:3005/payment-success?code=${code}`,
//         );
//       } else {
//         // PENDING: Webhook is still processing, but payment is confirmed
//         return res.redirect(
//           `http://localhost:3005/payment-success?ref=${reference}&status=pending`,
//         );
//       }
//     }

//     res.redirect(`http://localhost:3005/payment-failure`);
//   } catch (err) {
//     console.error("Callback verification failed:", err.message);
//     res.redirect(`http://localhost:3005/payment-failure`);
//   }
// });

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
