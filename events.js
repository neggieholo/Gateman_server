import express from "express";
import pool from "./db.js";
import {
  isAuth,
  ensureAdmin,
  verifyPermission,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import {
  createAppAuditLog,
  normalizeLocationLocalDateString,
} from "./helpers.js";

const router = express.Router();

// Normalizes any string/ISO date into a pure, timezone-locked YYYY-MM-DD format
const normalizeToLocalDateString = (dateInput) => {
  if (!dateInput) return null;
  const d = new Date(dateInput);
  if (isNaN(d.getTime())) return dateInput; // Fallback if it's already a clean string split

  const yyyy = d.getFullYear();
  const mm = String(d.getMonth() + 1).padStart(2, "0");
  const dd = String(d.getDate()).padStart(2, "0");
  return `${yyyy}-${mm}-${dd}`;
};

router.use(isAuth);

// --- 1. CREATE VENUE BOOKING ---
router.post(
  "/create",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  async (req, res) => {
    const {
      start_date,
      end_date,
      venue_id,
      venue_name,
      booked_dates_list,
      isPaid,
      estate_id,
    } = req.body;

    const { id: resident_id } = req.user;
    console.log("Bookig location:", req.body);

    if (
      !venue_id ||
      !venue_name ||
      !estate_id ||
      !Array.isArray(booked_dates_list) ||
      booked_dates_list.length === 0
    ) {
      return res.status(400).json({
        error:
          "Missing required venue asset selections, estate ID, or targeted booking dates list.",
      });
    }

    // 1. Extract clean date strings for array insertion
    const cleanBookedDatesList = booked_dates_list.map((d) => {
      const dateStr = typeof d === "string" ? d : d?.date;
      return normalizeLocationLocalDateString(dateStr);
    });

    const cleanStartDate =
      normalizeLocationLocalDateString(start_date) || cleanBookedDatesList[0];
    const cleanEndDate =
      normalizeLocationLocalDateString(end_date) ||
      cleanBookedDatesList[cleanBookedDatesList.length - 1];

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // Fetch facility payment details
      const facilityRes = await client.query(
        `SELECT is_paid, booking_rate, booking_rate_unit, event_booked_on 
         FROM estate_locations 
         WHERE id = $1 AND estate_id = $2`,
        [parseInt(venue_id, 10), estate_id],
      );

      if (facilityRes.rows.length === 0) {
        await client.query("ROLLBACK");
        return res
          .status(404)
          .json({ error: "Selected venue facility not found." });
      }

      const facility = facilityRes.rows[0];
      const isPaidBooking = Boolean(facility.is_paid || isPaid);

      // Auto-approve unpaid bookings; set paid bookings to pending approval
      const bookingStatus = isPaidBooking ? "PENDING_APPROVAL" : "APPROVED";

      let totalAmount = 0;

      // Calculate total rate safely from per-date slots if paid
      if (isPaidBooking) {
        const rate = parseFloat(facility.booking_rate) || 0;
        const unit = facility.booking_rate_unit;

        if (unit === "per_day") {
          totalAmount = rate * cleanBookedDatesList.length;
        } else if (unit === "per_hour") {
          let totalMinutes = 0;

          for (const item of booked_dates_list) {
            const slotStart = item.start_time;
            const slotEnd = item.end_time;

            if (!slotStart || !slotEnd) continue;

            const [startH, startM] = slotStart.split(":").map(Number);
            const [endH, endM] = slotEnd.split(":").map(Number);

            let diffMinutes = endH * 60 + endM - (startH * 60 + startM);
            if (diffMinutes <= 0) diffMinutes += 24 * 60; // Handle overnight wrapping

            totalMinutes += diffMinutes;
          }

          totalAmount = rate * (totalMinutes / 60);
        } else if (unit === "per_event") {
          totalAmount = rate;
        }
      }

      const cleanedSlots = booked_dates_list.map((item) => {
        if (typeof item === "string") return { date: item };
        const { resident_id, ...rest } = item;
        return rest;
      });

      const insertQuery = `
        INSERT INTO location_bookings (
          estate_id, resident_id, venue_id, venue_name,
          start_date, end_date, booked_dates, is_paid, status, total_amount
        ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10) 
        RETURNING *`;

      const values = [
        estate_id,
        resident_id,
        parseInt(venue_id, 10),
        venue_name,
        cleanStartDate,
        cleanEndDate,
        JSON.stringify(cleanedSlots),
        isPaidBooking,
        bookingStatus,
        totalAmount,
      ];

      const result = await client.query(insertQuery, values);
      const newBooking = result.rows[0];

      // 3. Update estate_locations with FOR UPDATE locking if auto-approved
      if (!isPaidBooking) {
        const locationLockRes = await client.query(
          `SELECT event_booked_on 
           FROM estate_locations 
           WHERE id = $1 AND estate_id = $2 
           FOR UPDATE`,
          [parseInt(venue_id, 10), estate_id],
        );

        if (locationLockRes.rows.length > 0) {
          let currentBookedOnMap =
            locationLockRes.rows[0].event_booked_on || {};

          if (typeof currentBookedOnMap === "string") {
            currentBookedOnMap = JSON.parse(currentBookedOnMap);
          }

          const mapKey = newBooking.id.toString();

          currentBookedOnMap[mapKey] = {
            dates: booked_dates_list,
          };

          await client.query(
            `UPDATE estate_locations 
             SET event_booked_on = $1 
             WHERE id = $2 AND estate_id = $3`,
            [
              JSON.stringify(currentBookedOnMap),
              parseInt(venue_id, 10),
              estate_id,
            ],
          );
        }
      }

      await client.query("COMMIT");

      const responseMessage = isPaidBooking
        ? "Venue booking submitted for management review"
        : "Venue booking confirmed and approved";

      res.status(201).json({
        message: responseMessage,
        booking: newBooking,
      });

      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "ESTATE_LOCATION_BOOKING_CREATED",
        target_resource: "location_bookings",
        target_id: newBooking.id,
        description: `Filed a new venue reservation at "${venue_name}" (ID: ${venue_id}). Status: ${bookingStatus}. Total: ₦${totalAmount}`,
        state_before: null,
        state_after: {
          ...newBooking,
          meta_audit_context: {
            total_days_blocked: cleanBookedDatesList.length,
            calculated_amount: totalAmount,
            auto_approved: !isPaidBooking,
          },
        },
        urgency: "INFO",
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Create Booking Error:", err);
      res.status(500).json({ error: "Failed to create venue booking" });
    } finally {
      client.release();
    }
  },
);
// --- 2. GET ALL BOOKINGS (For specific Estate Admin View) ---
router.get(
  "/all/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("view_facility_bookings", "facility_management"),
  async (req, res) => {
    const { estate_id } = req.params;
    try {
      const bookings = await pool.query(
        "SELECT * FROM location_bookings WHERE estate_id = $1 ORDER BY start_date ASC",
        [estate_id],
      );
      res.json(bookings.rows);
    } catch (err) {
      console.error("Fetch all bookings error:", err);
      res.status(500).json({ error: "Failed to fetch location bookings" });
    }
  },
);

// --- 3. GET ALL BOOKINGS (For specific Resident View) ---
router.post(
  "/resident/all",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  async (req, res) => {
    const { id } = req.user; // User ID acting as resident_id
    const { estate_id } = req.body;

    if (!estate_id) {
      return res.status(400).json({ error: "estate_id is required" });
    }

    try {
      const bookings = await pool.query(
        "SELECT * FROM location_bookings WHERE resident_id = $1 AND estate_id = $2 ORDER BY start_date ASC",
        [id, estate_id],
      );
      res.json(bookings.rows);
    } catch (err) {
      console.error("Fetch resident bookings error:", err);
      res.status(500).json({ error: "Failed to fetch personal bookings" });
    }
  },
);

// --- 4. SUBMIT PAYMENT PROOF (For Resident) ---
router.patch(
  "/submit-payment/:id",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  async (req, res) => {
    const { id: booking_id } = req.params;
    const { id: resident_id } = req.user;
    const { payment_url, payment_type, estate_id } = req.body;
    console.log("Payment body:", req.body);

    if (!payment_url) {
      return res.status(400).json({
        success: false,
        message: "Both receipt URL and transaction reference are required.",
      });
    }

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Fetch current booking to ensure ownership & track state change
      const existingResult = await client.query(
        `SELECT * FROM location_bookings WHERE id = $1 AND resident_id = $2`,
        [booking_id, resident_id],
      );

      if (existingResult.rows.length === 0) {
        await client.query("ROLLBACK");
        return res.status(404).json({
          success: false,
          message:
            "Booking not found or you do not have permission to update it.",
        });
      }

      const stateBefore = existingResult.rows[0];

      // Optional check: ensure it's in PAYMENT_PENDING status
      if (stateBefore.status !== "PAYMENT_PENDING") {
        await client.query("ROLLBACK");
        return res.status(400).json({
          success: false,
          message: `Cannot submit payment for a booking with status "${stateBefore.status}".`,
        });
      }

      // 2. Update booking status and payment fields
      const updateQuery = `
      UPDATE location_bookings
      SET 
        status = 'PAYMENT_SUBMITTED',
        payment_url = $1,
        payment_type = COALESCE($2, payment_type)
      WHERE id = $3 AND resident_id = $4
      RETURNING *;
    `;

      const updateValues = [
        payment_url,
        // transaction_ref,
        payment_type || null,
        booking_id,
        resident_id,
      ];

      const result = await client.query(updateQuery, updateValues);
      const updatedBooking = result.rows[0];

      // 3. Create a record in payment_logs
      const residentName =
        req.user.name ||
        req.user.full_name ||
        `${req.user.first_name || ""} ${req.user.last_name || ""}`.trim() ||
        "Resident";

      const paymentAmount =
        updatedBooking.total_amount || updatedBooking.amount || 0;

      const insertPaymentLogQuery = `
      INSERT INTO payment_logs (
        resident_id,
        estate_id,
        amount,
        receipt_url,
        status,
        payment_type,
        category,
        notes,
        resident_name,
        payment_date
      ) VALUES ($1, $2, $3, $4, 'pending', $5, 'location-booking', $6, $7, NOW())
      RETURNING id;
    `;

      const paymentLogValues = [
        resident_id,
        updatedBooking.estate_id,
        paymentAmount,
        // transaction_ref,
        payment_url,
        payment_type || "TRANSFER",
        `Payment submitted for venue booking: "${updatedBooking.venue_name}"`,
        residentName,
      ];

      await client.query(insertPaymentLogQuery, paymentLogValues);

      await client.query("COMMIT");

      // 4. Return response to client
      res.status(200).json({
        success: true,
        message: "Payment receipt submitted successfully!",
        booking: updatedBooking,
      });

      // 5. Audit logging (Asynchronous)
      await createAppAuditLog(req, {
        estate_id: updatedBooking.estate_id,
        action_type: "ESTATE_LOCATION_BOOKING_PAYMENT_SUBMITTED",
        target_resource: "location_bookings",
        target_id: updatedBooking.id,
        description: `Submitted payment proof for venue "${updatedBooking.venue_name}".`,
        state_before: stateBefore,
        state_after: updatedBooking,
        urgency: "INFO",
      });
    } catch (err) {
      await client.query("ROLLBACK");
      console.error("Submit Payment Error:", err);
      res.status(500).json({
        success: false,
        message: "Failed to process payment submission.",
      });
    } finally {
      client.release();
    }
  },
);

// --- 4. DELETE / CANCEL BOOKING ---
router.delete(
  "/delete/:id",
  verifyPlanModule("facility_bookings"),
  async (req, res) => {
    try {
      const { id } = req.params;

      // Fetch the entire record state before purging it
      const check = await pool.query(
        "SELECT * FROM location_bookings WHERE id = $1",
        [id],
      );

      if (check.rows.length === 0) {
        return res.status(404).json({ error: "Booking record not found" });
      }

      const bookingData = check.rows[0];

      // Ensure users can only drop their own personal bookings
      if (bookingData.resident_id !== req.user.id) {
        return res
          .status(403)
          .json({ error: "Unauthorized to cancel this booking reservation" });
      }

      // Perform hard delete
      await pool.query("DELETE FROM location_bookings WHERE id = $1", [id]);

      // 1. Respond to client instantly
      res.json({ message: "Venue reservation cancelled successfully" });

      // 2. Document destructive action asynchronously
      await createAppAuditLog(req, {
        estate_id: bookingData.estate_id || req.user.estate_id || null,
        action_type: "ESTATE_LOCATION_BOOKING_DELETED",
        target_resource: "location_bookings",
        target_id: id,
        description: `Resident cancelled booking at "${bookingData.venue_name}". Released blocked calendar dates: ${JSON.stringify(bookingData.booked_dates)}.`,
        state_before: bookingData,
        state_after: null,
        urgency: "INFO",
      });
    } catch (err) {
      console.error("Delete Booking Error:", err);
      res.status(500).json({ error: "Cancellation processing failed" });
    }
  },
);

router.patch(
  "/approve/:booking_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("manage_facility_bookings", "facility_management"),
  async (req, res) => {
    const { booking_id } = req.params;
    const { verdict, estate_id } = req.body;

    // 1. Array fix & Validation logic fix
    const statusOptions = ["APPROVED", "PAYMENT_PENDING", "REJECTED"];

    if (!verdict || !statusOptions.includes(verdict)) {
      return res
        .status(400)
        .json({ error: "Invalid verdict option provided." });
    }

    const client = await pool.connect();

    try {
      const beforeCheck = await client.query(
        `SELECT * FROM location_bookings WHERE id = $1 AND estate_id = $2`,
        [booking_id, estate_id],
      );

      if (beforeCheck.rowCount === 0) {
        client.release();
        return res
          .status(404)
          .json({ error: "Booking record not found in your estate." });
      }

      const bookingStateBefore = beforeCheck.rows[0];

      await client.query("BEGIN");

      // 2. Update booking status
      const updateBookingQuery = `
      UPDATE location_bookings 
      SET status = $1
      WHERE id = $2 AND estate_id = $3
      RETURNING *;`;

      const bookingRes = await client.query(updateBookingQuery, [
        verdict,
        booking_id,
        estate_id,
      ]);

      const booking = bookingRes.rows[0];
      const targetVenueId = booking.venue_id;

      if (targetVenueId) {
        // Look up and lock target facility using its explicit integer ID
        const locationLockRes = await client.query(
          `SELECT event_booked_on FROM estate_locations WHERE id = $1 AND estate_id = $2 FOR UPDATE`,
          [targetVenueId, estate_id],
        );

        if (locationLockRes.rows.length > 0) {
          let currentBookedOnMap =
            locationLockRes.rows[0].event_booked_on || {};
          if (typeof currentBookedOnMap === "string") {
            currentBookedOnMap = JSON.parse(currentBookedOnMap);
          }

          const mapKey = booking_id.toString();

          if (verdict === "APPROVED") {
            const formattedDates = (booking.booked_dates || []).map((d) =>
              normalizeToLocalDateString(d),
            );

            currentBookedOnMap[mapKey] = {
              venue_name: booking.venue_name,
              dates: formattedDates,
            };
          } else if (verdict === "REJECTED") {
            delete currentBookedOnMap[mapKey];
          }

          await client.query(
            `UPDATE estate_locations SET event_booked_on = $1 WHERE id = $2 AND estate_id = $3`,
            [JSON.stringify(currentBookedOnMap), targetVenueId, estate_id],
          );
        }
      }

      // Safe extraction of tenant/resident name string
      const residentRes = await client.query(
        `SELECT name FROM tenant_users WHERE id = $1`,
        [booking.resident_id],
      );
      const residentName = residentRes.rows[0]?.name || "Unknown Resident";

      await client.query("COMMIT");

      // Fetch refreshed target location metadata state
      const updatedLocationRes = await client.query(
        `SELECT * FROM estate_locations WHERE id = $1 AND estate_id = $2`,
        [targetVenueId, estate_id],
      );

      const locationRow = updatedLocationRes.rows[0];

      // 3. Respond with clear dynamic status messaging
      res.json({
        success: true,
        message:
          verdict === "APPROVED"
            ? "Venue booking approved and dates secured successfully!"
            : verdict === "PAYMENT_PENDING"
              ? "Booking updated to pending payment."
              : "Venue booking rejected and slots released.",
        booking,
        updatedLocation: locationRow,
      });

      // 4. Classify operational action parameters dynamically
      const judgmentNamespace = verdict.toUpperCase().trim();
      const dynamicActionType = `VENUE_BOOKING_${judgmentNamespace}`;

      // 5. Track operation footprints asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: dynamicActionType,
        target_resource: "location_bookings",
        target_id: booking_id,
        description: `Admin updated the booking with a verdict of ${verdict} for the booking request at "${booking.venue_name}" for resident: ${residentName}.`,
        state_before: bookingStateBefore,
        state_after: {
          ...booking,
          meta_audit_context: {
            allocated_location_state: locationRow || null,
          },
        },
        urgency: "MEDIUM",
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("Booking Approval processing failure:", err);
      res
        .status(500)
        .json({ error: "Server error during booking validation updates." });
    } finally {
      client.release();
    }
  },
);

// --- CREATE INSTANTLY APPROVED BOOKING ---
router.post(
  "/create-auto-approved",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("view_community_posts", "community_management"),
  async (req, res) => {
    const {
      start_date,
      end_date,
      start_time,
      end_time,
      venue_id, // Expects an integer ID linking to estate_locations
      venue_name, // Text representation
      booked_dates_list,
      estate_id,
      resident_id,
    } = req.body;

    if (
      !venue_id ||
      !venue_name ||
      !Array.isArray(booked_dates_list) ||
      booked_dates_list.length === 0
    ) {
      return res.status(400).json({
        error:
          "Missing required venue assets mapping fields, fallback label, or target blocked dates collection.",
      });
    }

    const cleanStartDate = normalizeToLocalDateString(start_date);
    const cleanEndDate = normalizeToLocalDateString(end_date);
    const cleanBookedDatesList = booked_dates_list.map((d) =>
      normalizeToLocalDateString(d),
    );

    const client = await pool.connect();

    try {
      await client.query("BEGIN");

      // 1. Insert directly with approved flag set to true, rejected to false
      const insertQuery = `
      INSERT INTO location_bookings (
        estate_id, resident_id, venue_id, venue_name,
        start_date, end_date, start_time, end_time, 
        booked_dates, is_approved, is_rejected
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, true, false) 
      RETURNING *`;

      const values = [
        estate_id,
        resident_id,
        parseInt(venue_id, 10),
        venue_name,
        cleanStartDate,
        cleanEndDate,
        start_time,
        end_time,
        cleanBookedDatesList,
      ];

      const result = await client.query(insertQuery, values);
      const newBooking = result.rows[0];

      // 2. Lock and auto-populate the layout matrix directly onto estate_locations
      const locationLockRes = await client.query(
        `SELECT event_booked_on FROM estate_locations WHERE id = $1 AND estate_id = $2 FOR UPDATE`,
        [parseInt(venue_id, 10), estate_id],
      );

      if (locationLockRes.rows.length > 0) {
        let currentBookedOnMap = locationLockRes.rows[0].event_booked_on || {};
        if (typeof currentBookedOnMap === "string") {
          currentBookedOnMap = JSON.parse(currentBookedOnMap);
        }

        // Key the reservation array directly on the generated entry row primary id
        const mapKey = newBooking.id.toString();

        currentBookedOnMap[mapKey] = {
          venue_name: venue_name,
          dates: cleanBookedDatesList,
        };

        await client.query(
          `UPDATE estate_locations SET event_booked_on = $1 WHERE id = $2 AND estate_id = $3`,
          [
            JSON.stringify(currentBookedOnMap),
            parseInt(venue_id, 10),
            estate_id,
          ],
        );
      }

      await client.query("COMMIT");

      // 3. Respond back with completed context structure
      res.status(201).json({
        success: true,
        message:
          "Venue reservation confirmed and applied directly to calendar registers.",
        booking: newBooking,
      });

      // 4. Create standard low friction application log footprints asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "VENUE_BOOKING_AUTO_APPROVED",
        target_resource: "location_bookings",
        target_id: newBooking.id,
        description: `System auto-confirmed location reservation for resident ID ${resident_id} at "${venue_name}" (ID: ${venue_id}).`,
        state_before: null,
        state_after: newBooking,
        urgency: "INFO",
      });
    } catch (err) {
      await client.query("ROLLBACK").catch(() => {});
      console.error("Auto-Approved Booking Processing Error:", err);
      res.status(500).json({
        error: "System failed to process instant reservation updates.",
      });
    } finally {
      client.release();
    }
  },
);

// --- CREATE LOCATION ROUTE ---
router.post(
  "/locations/create",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("configure_facilities", "facility_management"),
  async (req, res) => {
    const {
      name,
      location_in_estate,
      permitted_days,
      event_booked_on,
      capacity,
      isPaid,
      bookingDurationHours,
      bookingDurationMinutes,
      bookingRate,
      bookingRateUnit,
      isActive,
      estate_id,
    } = req.body;

    if (!name) {
      return res.status(400).json({ error: "Location name is required" });
    }

    const trimmedName = name.trim();

    try {
      const existingCheckQuery = `
      SELECT id FROM estate_locations 
      WHERE estate_id = $1 AND LOWER(name) = LOWER($2)
    `;
      const existingCheckResult = await pool.query(existingCheckQuery, [
        estate_id,
        trimmedName,
      ]);

      if (existingCheckResult.rows.length > 0) {
        return res.status(400).json({
          error: `A location named "${trimmedName}" already exists in this estate.`,
        });
      }

      const parsedRate = isPaid && bookingRate ? parseFloat(bookingRate) : null;

      const query = `
      INSERT INTO estate_locations (
        estate_id, name, location_in_estate, permitted_days, 
        event_booked_on, capacity, is_active, is_paid, 
        booking_rate, booking_rate_unit, booking_duration_hours, booking_duration_minutes
      )
      VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
      RETURNING *`;

      const values = [
        estate_id,
        name,
        location_in_estate || null,
        JSON.stringify(permitted_days || []),
        JSON.stringify(event_booked_on || {}),
        capacity || null,
        isActive !== undefined ? isActive : true,
        isPaid || false,
        parsedRate,
        isPaid && bookingRateUnit ? bookingRateUnit : null,
        bookingDurationHours !== undefined && bookingDurationHours !== null
          ? Number(bookingDurationHours)
          : null,
        bookingDurationMinutes !== undefined && bookingDurationMinutes !== null
          ? Number(bookingDurationMinutes)
          : null,
      ];

      const result = await pool.query(query, values);
      const newLocation = result.rows[0];

      // 1. Respond to admin client instantly
      res.status(201).json(newLocation);

      // 2. Track new resource footprint asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "LOCATION_ASSET_CREATED",
        target_resource: "estate_locations",
        target_id: newLocation.id,
        description: `Admin registered a new bookable estate venue asset: "${name}" (Capacity: ${capacity || "Unspecified"}, Type: ${isPaid ? "Paid" : "Free"}).`,
        state_before: null,
        state_after: newLocation,
        urgency: "INFO",
      });
    } catch (err) {
      console.error("Create location error:", err);
      res.status(500).json({ error: "Failed to create estate location" });
    }
  },
);
// --- EDIT LOCATION ROUTE ---
router.put(
  "/locations/edit/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("configure_facilities", "facility_management"),
  async (req, res) => {
    const { id } = req.params;
    const locationId = parseInt(id, 10);

    const {
      name,
      location_in_estate,
      permitted_days,
      capacity,
      isPaid,
      is_paid,
      bookingDurationHours,
      bookingDurationMinutes,
      bookingRate,
      bookingRateUnit,
      isActive,
      is_active,
      estate_id,
    } = req.body;

    if (!name) {
      return res.status(400).json({ error: "Location name cannot be empty" });
    }

    try {
      // 🧠 Fetch snapshot BEFORE modification to capture structural changes
      const preCheck = await pool.query(
        "SELECT * FROM estate_locations WHERE id = $1 AND estate_id = $2",
        [locationId, estate_id],
      );

      if (preCheck.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Location asset update target missing" });
      }

      const locationStateBefore = preCheck.rows[0];

      const activeStatus =
        is_active !== undefined
          ? is_active
          : isActive !== undefined
            ? isActive
            : true;
      const paidStatus = is_paid !== undefined ? is_paid : isPaid || false;
      const parsedRate =
        paidStatus && bookingRate ? parseFloat(bookingRate) : null;

      const query = `
      UPDATE estate_locations
      SET name = $1, 
          location_in_estate = $2, 
          permitted_days = $3::jsonb, 
          capacity = $4,
          is_active = $5,
          is_paid = $6,
          booking_rate = $7,
          booking_rate_unit = $8,
          booking_duration_hours = $9, 
          booking_duration_minutes = $10
      WHERE id = $11 AND estate_id = $12
      RETURNING *`;

      const values = [
        name,
        location_in_estate || null,
        JSON.stringify(permitted_days || []), // Must be stringified for JSONB!
        capacity ? parseInt(capacity, 10) : null,
        Boolean(activeStatus),
        Boolean(paidStatus),
        parsedRate,
        paidStatus && bookingRateUnit ? bookingRateUnit : null,
        bookingDurationHours !== undefined && bookingDurationHours !== null
          ? parseInt(bookingDurationHours, 10)
          : null,
        bookingDurationMinutes !== undefined && bookingDurationMinutes !== null
          ? parseInt(bookingDurationMinutes, 10)
          : null,
        locationId,
        estate_id,
      ];

      const result = await pool.query(query, values);
      const updatedLocation = result.rows[0];

      // 1. Respond to admin client instantly
      res.json({
        message: "Location updated successfully",
        location: updatedLocation,
      });

      // 2. Track asset modification footprint asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "LOCATION_ASSET_MODIFIED",
        target_resource: "estate_locations",
        target_id: locationId,
        description: `Admin updated configurations for estate venue asset "${name}" (ID: ${locationId}).`,
        state_before: locationStateBefore,
        state_after: updatedLocation,
        urgency: "MEDIUM",
      });
    } catch (err) {
      console.error("Update location error:", err);
      res.status(500).json({ error: "Failed to modify location asset" });
    }
  },
);

// --- GET ALL LOCATIONS (For Admin Estate context) ---
router.get(
  "/locations/all/:estate_id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("configure_facilities", "facility_management"),
  async (req, res) => {
    const { estate_id } = req.params;
    try {
      const locations = await pool.query(
        "SELECT * FROM estate_locations WHERE estate_id = $1 ORDER BY name ASC",
        [estate_id],
      );
      res.json(locations.rows);
    } catch (err) {
      console.error("Fetch locations error:", err);
      res.status(500).json({ error: "Failed to fetch estate locations" });
    }
  },
);

router.post(
  "/locations/tenant/all",
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  async (req, res) => {
    const { estate_id } = req.body;
    try {
      const locations = await pool.query(
        "SELECT * FROM estate_locations WHERE estate_id = $1 ORDER BY name ASC",
        [estate_id],
      );
      res.json(locations.rows);
    } catch (err) {
      console.error("Fetch locations error:", err);
      res.status(500).json({ error: "Failed to fetch estate locations" });
    }
  },
);

// --- GET A PARTICULAR LOCATION ---
router.get(
  "/locations/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("configure_facilities", "facility_management"),
  async (req, res) => {
    const { id } = req.params;
    const { estate_id } = req.query;
    try {
      const location = await pool.query(
        "SELECT * FROM estate_locations WHERE id = $1 AND estate_id = $2",
        [id, estate_id],
      );

      if (location.rows.length === 0) {
        return res.status(404).json({ error: "Location asset not found" });
      }
      res.json(location.rows[0]);
    } catch (err) {
      console.error("Fetch single location error:", err);
      res.status(500).json({ error: "Failed to fetch location details" });
    }
  },
);

// --- DELETE LOCATION ---
router.delete(
  "/locations/delete/:id",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("configure_facilities", "facility_management"),
  async (req, res) => {
    const { id } = req.params;
    const { estate_id } = req.query;

    try {
      const result = await pool.query(
        "DELETE FROM estate_locations WHERE id = $1 AND estate_id = $2 RETURNING *",
        [id, estate_id],
      );

      if (result.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Location asset erasure target missing" });
      }

      const purgedLocationData = result.rows[0];

      // 1. Respond to admin client instantly
      res.json({ message: "Location resource purged successfully" });

      // 2. Track destructive purge asynchronously
      await createAppAuditLog(req, {
        estate_id: estate_id,
        action_type: "LOCATION_ASSET_PURGED",
        target_resource: "estate_locations",
        target_id: id,
        description: `Admin permanently removed venue asset "${purgedLocationData.name}" from the estate catalog.`,
        state_before: purgedLocationData,
        state_after: null,
        urgency: "WARNING",
      });
    } catch (err) {
      console.error("Delete location error:", err);
      res.status(500).json({ error: "Failed to erase location asset" });
    }
  },
);

// --- GET EVENT BY LOCATION ASSET AND SPECIFIC DATE ---
router.get(
  "/locations/:id/event-at-date",
  ensureAdmin,
  authorizeEstate,
  verifyEstateSubscription,
  verifyPlanModule("facility_bookings"),
  verifyPermission("configure_facilities", "facility_management"),
  async (req, res) => {
    const { id } = req.params;
    const { date, estate_id } = req.query;

    if (!date) {
      return res
        .status(400)
        .json({ error: "Date parameter (?date=) is required" });
    }

    try {
      const locResult = await pool.query(
        "SELECT event_booked_on FROM estate_locations WHERE id = $1 AND estate_id = $2",
        [id, estate_id],
      );

      if (locResult.rows.length === 0) {
        return res.status(404).json({ error: "Location asset target missing" });
      }

      let eventBookedOn = locResult.rows[0].event_booked_on || {};
      if (typeof eventBookedOn === "string") {
        try {
          eventBookedOn = JSON.parse(eventBookedOn);
        } catch (parseErr) {
          console.error("JSON parsing error on event_booked_on:", parseErr);
          return res.json({ booking: [] });
        }
      }

      // Normalize search date to DD-MM-YYYY
      let searchDateStr = String(date).split("T")[0];
      if (
        searchDateStr.includes("-") &&
        searchDateStr.split("-")[0].length === 4
      ) {
        const [yyyy, mm, dd] = searchDateStr.split("-");
        searchDateStr = `${dd}-${mm}-${yyyy}`;
      }

      const matchedBookings = [];

      for (const [eventId, bookingContext] of Object.entries(eventBookedOn)) {
        if (bookingContext && typeof bookingContext === "object") {
          const { dates } = bookingContext;

          if (Array.isArray(dates)) {
            const matchedSlot = dates.find((item) => {
              const rawDate = typeof item === "string" ? item : item?.date;
              if (!rawDate) return false;

              let cleanDate = rawDate.split("T")[0];
              if (
                cleanDate.includes("-") &&
                cleanDate.split("-")[0].length === 4
              ) {
                const [yyyy, mm, dd] = cleanDate.split("-");
                cleanDate = `${dd}-${mm}-${yyyy}`;
              }

              return cleanDate === searchDateStr;
            });

            if (matchedSlot) {
              matchedBookings.push({
                booking_id: eventId,
                ...(typeof matchedSlot === "object"
                  ? matchedSlot
                  : { date: matchedSlot }),
              });
            }
          }
        }
      }

      return res.json({ booking: matchedBookings });
    } catch (err) {
      console.error("Fetch booking at location date error:", err);
      return res
        .status(500)
        .json({ error: "Failed to isolate event scheduling information" });
    }
  },
);

const checkExpiredBookings = async () => {
  console.log("Running Two-Phase Expired Facility Bookings Cleanup...");
  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const fetchForDeletionQuery = `
      SELECT id, venue_id 
      FROM location_bookings
      WHERE is_expired = TRUE
      FOR UPDATE;
    `;

    const { rows: toDelete } = await client.query(fetchForDeletionQuery);

    if (toDelete.length > 0) {
      // 1A. Drop top-level UUID key from estate_locations.event_booked_on
      for (const booking of toDelete) {
        const bookingIdStr = String(booking.id);
        await client.query(
          `UPDATE estate_locations 
           SET event_booked_on = event_booked_on - $1 
           WHERE id = $2 AND event_booked_on ? $1`,
          [bookingIdStr, booking.venue_id],
        );
      }

      // 1B. Delete the rows from location_bookings
      const deleteIds = toDelete.map((b) => b.id);
      const deleteResult = await client.query(
        `DELETE FROM location_bookings WHERE id = ANY($1::uuid[])`, // or $1::int[] if ID is integer
        [deleteIds],
      );
      console.log(
        `🧹 Phase 1: Permanently purged ${deleteResult.rowCount} previously expired bookings.`,
      );
    }

    // Since end_date is a DATE or TIMESTAMP, cast directly to DATE and add the end-of-day time
    const markExpiredQuery = `
      UPDATE location_bookings
      SET is_expired = TRUE
      WHERE is_expired = FALSE
        AND (end_date::date + TIME '23:59:59') < NOW()
      RETURNING id;
    `;

    const { rows: newlyExpired } = await client.query(markExpiredQuery);
    if (newlyExpired.length > 0) {
      console.log(
        `🏷️ Phase 2: Labeled ${newlyExpired.length} elapsed bookings as is_expired = true.`,
      );
    }

    await client.query("COMMIT");
  } catch (err) {
    await client.query("ROLLBACK");
    console.error("❌ Expired Bookings Two-Phase Sweep Error:", err);
  } finally {
    client.release();
  }
};

export { checkExpiredBookings };

export default router;
