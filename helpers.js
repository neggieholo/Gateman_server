import pool from "./db.js";
import { parseUserAgent } from "./middlewares.js";
import { S3Client, PutObjectCommand } from "@aws-sdk/client-s3";
import { getSignedUrl } from "@aws-sdk/s3-request-presigner";
import crypto from "crypto";

export const createAuditLog = async (
  req,
  {
    action_type,
    target_resource,
    target_id,
    description,
    state_before = null,
    state_after = null,
    log_type,
    urgency = "medium",
  },
) => {
  try {
    const actorId = req.user?.id || "00000000-0000-0000-0000-000000000000";
    const actorName = req.user?.full_name || "System / Automated";
    const actorEmail = req.user?.email || "system@gateman.com";

    const ipAddress =
      req.headers["x-forwarded-for"]?.split(",")[0].trim() ||
      req.socket.remoteAddress ||
      "0.0.0.0";
    const clientDevice = parseUserAgent(req.headers["user-agent"]);

    const logQuery = `
      INSERT INTO logs (
        user_id, user_name, user_email, 
        action_type, target_resource, target_id, 
        description, state_before, state_after, log_type,
        urgency, ip_address, user_agent
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13);
    `;

    await pool.query(logQuery, [
      actorId,
      actorName,
      actorEmail,
      action_type,
      target_resource,
      String(target_id),
      description,
      state_before ? JSON.stringify(state_before) : null,
      state_after ? JSON.stringify(state_after) : null,
      log_type,
      urgency,
      ipAddress,
      clientDevice,
    ]);
  } catch (logErr) {
    // Guard: Never let an audit log failure crash your core response path
    console.error(
      "🚨 CRITICAL: Audit Logging Engine failed to commit row:",
      logErr,
    );
  }
};

export const createAppAuditLog = async (
  req,
  {
    estate_id = null,
    action_type,
    target_resource,
    target_id = null,
    description,
    state_before = null,
    state_after = null,
    urgency = "MEDIUM",
  },
) => {
  try {
    const actorId = req.user?.id || "00000000-0000-0000-0000-000000000000";
    const actorName = req.user?.name || "System / Automated";
    const actorEmail = req.user?.email || "system@gateman.com";
    const actorRole = req.user?.role || "UNKNOWN"; // E.g., 'ESTATE_ADMIN', 'RESIDENT', 'SECURITY'

    const ipAddress = req.session?.ip || "0.0.0.0";
    const clientDevice = req.session?.userAgent || "Unknown Device";

    const logQuery = `
      INSERT INTO app_logs (
        estate_id, user_id, user_name, user_email, user_role,
        action_type, target_resource, target_id, 
        description, state_before, state_after,
        urgency, ip_address, user_agent
      ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14);
    `;

    await pool.query(logQuery, [
      estate_id || req.user?.estate_id || null,
      actorId,
      actorName,
      actorEmail,
      actorRole.toUpperCase().trim(),
      action_type.toUpperCase().trim(),
      target_resource,
      target_id ? String(target_id) : null,
      description,
      state_before ? JSON.stringify(state_before) : null,
      state_after ? JSON.stringify(state_after) : null,
      urgency.toUpperCase(),
      ipAddress,
      clientDevice,
    ]);
  } catch (logErr) {
    console.error(
      "🚨 CRITICAL: App Logging Engine failed to commit row:",
      logErr,
    );
  }
};

const s3Client = new S3Client({
  region: "eu-west-1",
  credentials: {
    accessKeyId: process.env.AWS_ACCESS_KEY_ID,
    secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY,
  },
});

const BUCKET_NAME = "gateman-hq";
const BASE_URL = `https://${BUCKET_NAME}.s3.eu-west-1.amazonaws.com`;

/**
 * 1. FOR FRONTEND: Generates a presigned PUT URL
 */
export async function getPresignedUploadUrl(
  fileName,
  fileType,
  folder = "selfies",
) {
  const sanitizeName = fileName.replace(/[^a-zA-Z0-9.-]/g, "_");
  const key = `${folder}/${Date.now()}-${sanitizeName}`;

  const command = new PutObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
    ContentType: fileType,
    ACL: "public-read",
  });

  // URL expires in 5 minutes (300 seconds)
  const uploadUrl = await getSignedUrl(s3Client, command, { expiresIn: 300 });
  const fileUrl = `${BASE_URL}/${key}`;

  return { uploadUrl, fileUrl, key };
}

export async function uploadToS3Direct(
  fileBuffer,
  mimeType,
  folder = "admin_uploads",
  originalName = "file.jpg",
) {
  const sanitizeName = originalName.replace(/[^a-zA-Z0-9.-]/g, "_");
  const key = `${folder}/${Date.now()}-${sanitizeName}`;

  const command = new PutObjectCommand({
    Bucket: BUCKET_NAME,
    Key: key,
    Body: fileBuffer,
    ContentType: mimeType,
    ACL: "public-read",
  });

  await s3Client.send(command);

  return `${BASE_URL}/${key}`;
}

export async function provisionEstateAccount(
  client,
  {
    tempUser,
    paidAmount,
    paymentChannel,
    reference,
    durationMonths,
    expiryDate,
    gatewayMetadata,
  },
) {
  // 1. Create Estate
  const estateCode = crypto.randomBytes(3).toString("hex").toUpperCase();
  const estateResult = await client.query(
    `INSERT INTO estates (name, estate_code, state, lga, street_address, root_admin, root_admin_email, plan, subscription_expiry)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
    [
      `${tempUser.name} Estate`,
      estateCode,
      tempUser.state,
      tempUser.lga,
      tempUser.street_address,
      tempUser.root_admin,
      tempUser.email,
      tempUser.plan,
      expiryDate,
    ],
  );
  const estateId = estateResult.rows[0].id;

  // 2. Insert or Update Admin
  const existingAdmin = await client.query(
    `SELECT id, estate_ids FROM estate_admin_users WHERE email = $1`,
    [tempUser.email],
  );

  if (tempUser.is_existing || existingAdmin.rows.length > 0) {
    await client.query(
      `UPDATE estate_admin_users 
       SET estate_ids = array_append(estate_ids, $1) 
       WHERE email = $2 AND NOT ($1 = ANY(estate_ids))`,
      [estateId, tempUser.email],
    );
  } else {
    await client.query(
      `INSERT INTO estate_admin_users 
       (estate_ids, email, password, role, name, email_verified, sub_account, permissions, must_change_password) 
       VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
      [
        [estateId],
        tempUser.email,
        tempUser.password,
        "ADMIN",
        tempUser.root_admin,
        true,
        false,
        ["all-access"],
        false,
      ],
    );
  }

  // 3. Insert Payment/Subscription Ledger Entry
  const startDate = new Date();
  await client.query(
    `INSERT INTO estate_subscription_payments (
      estate_id, processed_by_email, amount, currency, plan,
      payment_method, payment_reference, payment_status, state, country,
      coverage_start_date, coverage_end_date, duration_months, gateway_metadata
    ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14)`,
    [
      estateId,
      tempUser.email,
      paidAmount,
      "NGN",
      tempUser.plan,
      paymentChannel,
      reference,
      "SUCCESSFUL",
      tempUser.state || "Lagos",
      "Nigeria",
      startDate,
      expiryDate,
      durationMonths,
      JSON.stringify(gatewayMetadata),
    ],
  );

  return estateId;
}

export const formatDateString = (dateVal) => {
  if (!dateVal) return null;
  if (dateVal instanceof Date) {
    const y = dateVal.getFullYear();
    const m = String(dateVal.getMonth() + 1).padStart(2, "0");
    const d = String(dateVal.getDate()).padStart(2, "0");
    return `${y}-${m}-${d}`;
  }
  return String(dateVal).split("T")[0];
};

/**
 * Calculates concrete shift instances for current and next cycles based on recurring templates.
 */
// 1. Updated Specific Shifts Calculator
export function calculateSpecificShifts(specificDateGroups) {
  if (!Array.isArray(specificDateGroups)) {
    return { shifts: [], startDate: null, endDate: null };
  }

  const shifts = [];
  let minDate = null;
  let maxDate = null;

  specificDateGroups.forEach((group) => {
    const dateStr = group.date;
    const periods = group.periods || [];

    if (!dateStr) return;

    // Track cycle bounds across group dates
    if (!minDate || dateStr < minDate) minDate = dateStr;
    if (!maxDate || dateStr > maxDate) maxDate = dateStr;

    periods.forEach((period) => {
      const startOffset = period.startTimeDayOffset ?? 0;
      const endOffset = period.endTimeDayOffset ?? startOffset;

      const baseDate = new Date(dateStr + "T00:00:00Z");
      const startDateObj = new Date(baseDate);
      startDateObj.setUTCDate(startDateObj.getUTCDate() + startOffset);

      const endDateObj = new Date(baseDate);
      endDateObj.setUTCDate(endDateObj.getUTCDate() + endOffset);

      const assignedGuardIds = Array.isArray(period.assignedGuardIds)
        ? period.assignedGuardIds
        : [];

      shifts.push({
        period_id: period.id || null,
        label: period.label || "Shift Period",
        start_date: startDateObj.toISOString().split("T")[0],
        start_time: period.startTime,
        end_date: endDateObj.toISOString().split("T")[0],
        end_time: period.endTime,
        assigned_guard_ids: assignedGuardIds,
      });
    });
  });

  return {
    shifts,
    startDate: minDate,
    endDate: maxDate,
  };
}

// 2. Updated Recurring Schedule Projections Calculator
export function calculateScheduleProjections(
  cycleStartDateStr,
  cadence,
  recurringPeriods,
  scheduleEndDateStr = null,
) {
  const parseDate = (dStr) => {
    const [y, m, d] = dStr.split("-").map(Number);
    return new Date(Date.UTC(y, m - 1, d));
  };

  const formatDate = (dateObj) => dateObj.toISOString().split("T")[0];

  let cycleDays = 1;
  if (cadence === "weekly" || cadence === "weekday") cycleDays = 7;
  else if (cadence === "bi-weekly") cycleDays = 14;
  else if (cadence === "tri-weekly") cycleDays = 21;
  else if (cadence === "daily") {
    if (recurringPeriods && recurringPeriods.length > 0) {
      const minStartOffset = Math.min(
        ...recurringPeriods.map((p) => p.startTimeDayOffset ?? 0),
      );
      const maxEndOffset = Math.max(
        ...recurringPeriods.map(
          (p) => p.endTimeDayOffset ?? p.startTimeDayOffset ?? 0,
        ),
      );

      const rawSpan = maxEndOffset - minStartOffset;
      const lastPeriod = recurringPeriods[recurringPeriods.length - 1];
      const isLastOvernight =
        lastPeriod &&
        (lastPeriod.endTimeDayOffset ?? 0) >
          (lastPeriod.startTimeDayOffset ?? 0);

      cycleDays = Math.max(1, rawSpan + (isLastOvernight ? 1 : 0));
    } else {
      cycleDays = 1;
    }
  }

  const generateCycleShifts = (baseCycleStartDate) => {
    if (!recurringPeriods || !Array.isArray(recurringPeriods)) return [];

    return recurringPeriods
      .map((period) => {
        const startOffset = period.startTimeDayOffset ?? 0;
        const endOffset = period.endTimeDayOffset ?? startOffset;

        const shiftStart = new Date(baseCycleStartDate);
        shiftStart.setUTCDate(shiftStart.getUTCDate() + startOffset);

        const shiftEnd = new Date(baseCycleStartDate);
        shiftEnd.setUTCDate(shiftEnd.getUTCDate() + endOffset);

        const startDateFormatted = formatDate(shiftStart);
        let endDateFormatted = formatDate(shiftEnd);
        let shiftEndTime = period.endTime;

        if (scheduleEndDateStr && startDateFormatted > scheduleEndDateStr) {
          return null;
        }

        if (scheduleEndDateStr && endDateFormatted > scheduleEndDateStr) {
          endDateFormatted = scheduleEndDateStr;
          shiftEndTime = "23:59";
        }

        // Normalize assigned guard IDs as an array
        const assignedGuardIds = Array.isArray(period.assignedGuardIds)
          ? period.assignedGuardIds
          : period.guardId
            ? [period.guardId]
            : [];

        return {
          period_id: period.id || null,
          label: period.label || "Shift Period",
          start_date: startDateFormatted,
          start_time: period.startTime,
          end_date: endDateFormatted,
          end_time: shiftEndTime,
          assigned_guard_ids: assignedGuardIds,
        };
      })
      .filter((shift) => shift !== null);
  };

  const currentCycleStartDate = parseDate(cycleStartDateStr);

  const currentCycleEndDate = new Date(currentCycleStartDate);
  currentCycleEndDate.setUTCDate(currentCycleEndDate.getUTCDate() + cycleDays);

  const currentShifts = generateCycleShifts(currentCycleStartDate);

  const nextCycleStartDate = new Date(currentCycleEndDate);

  const nextCycleEndDate = new Date(nextCycleStartDate);
  nextCycleEndDate.setUTCDate(nextCycleEndDate.getUTCDate() + cycleDays);

  const nextCycleStartDateStr = formatDate(nextCycleStartDate);
  const nextCycleEndDateStr = formatDate(nextCycleEndDate);

  let nextShifts = [];
  if (!scheduleEndDateStr || nextCycleStartDateStr <= scheduleEndDateStr) {
    nextShifts = generateCycleShifts(nextCycleStartDate);
  }

  return {
    currentShifts,
    nextShifts,
    currentCycleStartDate: cycleStartDateStr,
    currentCycleEndDate: formatDate(currentCycleEndDate),
    nextCycleStartDate: nextCycleStartDateStr,
    nextCycleEndDate: nextCycleEndDateStr,
  };
}

/**
 * Cron task function: Checks all recurring projections and advances cycles
 * if the current cycle date window has elapsed.
 */
export async function advanceExpiredProjections() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const todayStr = new Date().toISOString().split("T")[0];

    // 1. Fetch projections where next_cycle_start_date is today or in the past
    const { rows: expiredProjections } = await client.query(
      `SELECT 
        p.*,
        s.start_date AS schedule_start_date,
        s.recurring_cadence,
        s.recurring_periods,
        s.end_date AS schedule_end_date
      FROM estate_security_schedule_projections p
      JOIN estate_security_schedules s ON p.schedule_id = s.id
      WHERE p.next_cycle_start_date <= $1 AND s.mode = 'recurring';      
    `,
      [todayStr],
    );

    for (const proj of expiredProjections) {
      const baseStartDate = proj.current_cycle_start_date
        ? formatDateString(proj.current_cycle_start_date)
        : formatDateString(proj.schedule_start_date);

      // 2. Generate new projection calculation
      const newProjections = calculateScheduleProjections(
        baseStartDate,
        proj.recurring_cadence,
        proj.recurring_periods,
        proj.schedule_end_date,
      );

      // 3. Promote next cycle -> current cycle, and assign freshly calculated values -> next cycle
      await client.query(
        `
        UPDATE estate_security_schedule_projections
        SET 
          current_cycle_shifts = $1,
          current_cycle_start_date = $2,
          current_cycle_end_date = $3,
          next_cycle_shifts = $4,
          next_cycle_start_date = $5,
          next_cycle_end_date = $6,
          updated_at = NOW()
        WHERE id = $7;
      `,
        [
          JSON.stringify(proj.next_cycle_shifts),
          proj.next_cycle_start_date,
          proj.next_cycle_end_date,
          JSON.stringify(newProjections.nextShifts),
          newProjections.nextCycleStartDate,
          newProjections.nextCycleEndDate,
          proj.id,
        ],
      );
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    throw error;
  } finally {
    client.release();
  }
}

// export function isShiftExpired(
//   shiftEndDateStr,
//   shiftEndTimeStr,
//   now = new Date(),
// ) {
//   const [endYear, endMonth, endDay] = shiftEndDateStr.split("-").map(Number);
//   const [endHour, endMinute] = shiftEndTimeStr.split(":").map(Number);

//   // Construct UTC shift end timestamp
//   const shiftEndTimestamp = new Date(
//     Date.UTC(endYear, endMonth - 1, endDay, endHour, endMinute, 0),
//   );

//   return now > shiftEndTimestamp;
// }

export async function verifyGuardActiveShift(req, res, next) {
  try {
    const user = req.user;

    // Only enforce shift boundaries for security personnel
    if (user?.role !== "SECURITY") {
      return next();
    }

    // ALWAYS use absolute server time
    const now = new Date();

    // 1. Fetch Guard Status from DB
    const { rows: guards } = await pool.query(
      "SELECT id, is_on_duty, estate_id FROM security_users WHERE id = $1",
      [user.id],
    );

    const guard = guards[0];
    if (!guard || !guard.is_on_duty) {
      return res.status(403).json({
        success: false,
        error:
          "You are currently off-duty. Please check in to perform this action.",
        message:
          "You are currently off-duty. Please check in to perform this action.",
      });
    }

    // 2. Fetch Active Schedule Projections for the Estate
    const { rows: projections } = await pool.query(
      `SELECT p.* 
       FROM estate_security_schedule_projections p
       JOIN estate_security_schedules s ON p.schedule_id = s.id
       WHERE s.estate_id = $1`,
      [guard.estate_id],
    );

    let activeShiftFound = null;

    for (const proj of projections) {
      const shifts = [
        ...(Array.isArray(proj.current_cycle_shifts)
          ? proj.current_cycle_shifts
          : JSON.parse(proj.current_cycle_shifts || "[]")),
      ];

      // Check if current server time falls inside ANY shift assigned to this guard
      const matched = shifts.find((s) => {
        const guardList = s.assigned_guard_ids || [];
        const isAssigned =
          Array.isArray(guardList) && guardList.includes(user.id);
        if (!isAssigned) return false;

        const shiftStart = new Date(`${s.start_date}T${s.start_time}`);
        const shiftEnd = new Date(`${s.end_date}T${s.end_time}`);

        // Server time must be within start and end boundary
        return now >= shiftStart && now <= shiftEnd;
      });

      if (matched) {
        activeShiftFound = matched;
        break;
      }
    }

    // 3. Reject request if no active shift matches current server time
    if (!activeShiftFound) {
      return res.status(403).json({
        success: false,
        error: "Your scheduled shift duration has ended. Please check out.",
        message: "Your scheduled shift duration has ended. Please check out.",
      });
    }

    // 4. Valid shift confirmed -> proceed
    next();
  } catch (error) {
    console.error("Shift verification middleware error:", error);
    res
      .status(500)
      .json({ error: "Failed to verify guard shift authorization." });
  }
}

/**
 * Cron task function: Checks all security guards currently marked on duty (`is_on_duty = TRUE`)
 * and automatically checks them out if they do not have an active assigned shift projection at the current time.
 */
export async function autoCheckoutOffScheduleGuards() {
  const client = await pool.connect();
  try {
    await client.query("BEGIN");

    const now = new Date();

    // 1. Fetch all guards who are currently marked on duty
    const { rows: onDutyGuards } = await client.query(`
      SELECT 
        id,
        name,
        estate_id,
        is_on_duty,
        checkin_location,
        checkin_address,
        last_checkin
      FROM security_users
      WHERE is_on_duty = TRUE;
    `);

    if (onDutyGuards.length === 0) {
      await client.query("COMMIT");
      return { autoCheckedOutCount: 0 };
    }

    const autoCheckedOutGuards = [];

    // Group active guards by estate_id to minimize projection database queries
    const estateGuardMap = new Map();
    for (const guard of onDutyGuards) {
      if (!estateGuardMap.has(guard.estate_id)) {
        estateGuardMap.set(guard.estate_id, []);
      }
      estateGuardMap.get(guard.estate_id).push(guard);
    }

    for (const [estateId, guards] of estateGuardMap.entries()) {
      // 2. Query schedule projections for this estate
      const { rows: projections } = await client.query(
        `SELECT p.* 
         FROM estate_security_schedule_projections p
         JOIN estate_security_schedules s ON p.schedule_id = s.id
         WHERE p.estate_id = $1`,
        [estateId],
      );

      for (const guard of guards) {
        let hasActiveShift = false;

        // 3. Evaluate whether guard is currently inside an active shift window
        for (const proj of projections) {
          const shifts = [
            ...(Array.isArray(proj.current_cycle_shifts)
              ? proj.current_cycle_shifts
              : JSON.parse(proj.current_cycle_shifts || "[]")),
            ...(Array.isArray(proj.next_cycle_shifts)
              ? proj.next_cycle_shifts
              : JSON.parse(proj.next_cycle_shifts || "[]")),
          ];

          const matchedShift = shifts.find((s) => {
            const guardList = s.assigned_guard_ids || [];
            const isAssigned =
              Array.isArray(guardList) && guardList.includes(guard.id);
            if (!isAssigned) return false;

            // Construct exact shift window timestamps
            const shiftStart = new Date(`${s.start_date}T${s.start_time}`);
            const shiftEnd = new Date(`${s.end_date}T${s.end_time}`);

            return now >= shiftStart && now <= shiftEnd;
          });

          if (matchedShift) {
            hasActiveShift = true;
            break;
          }
        }

        // 4. Auto-checkout guard if no active assigned shift projection covers current time
        if (!hasActiveShift) {
          // Update guard status in security_users
          const updateRes = await client.query(
            `UPDATE security_users 
             SET is_on_duty = FALSE, 
                 checkout_location = NULL,
                 last_known_location = NULL,
                 last_location_time = $1,
                 last_checkout = $1,
                 last_liveness_photo_url = NULL,
                 last_known_location_selfie = NULL,
                 checkout_address = NULL,
                 last_known_address = NULL
             WHERE id = $2 AND estate_id = $3
             RETURNING *`,
            [now, guard.id, estateId],
          );

          // Record auto-checkout action in duty log
          await client.query(
            `INSERT INTO security_duty_logs 
              (guard_id, estate_id, action, location, address, liveness_photo_url, actual_checkout_time)
             VALUES ($1, $2, $3, $4, $5, $6, $7)`,
            [guard.id, estateId, "CHECK_OUT", null, null, null, now],
          );

          autoCheckedOutGuards.push({
            guard_id: guard.id,
            guard_name: guard.name,
            estate_id: estateId,
            checked_out_at: now,
          });
        }
      }
    }

    await client.query("COMMIT");
    return {
      autoCheckedOutCount: autoCheckedOutGuards.length,
      guards: autoCheckedOutGuards,
    };
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("Error in autoCheckoutOffScheduleGuards:", error);
    throw error;
  } finally {
    client.release();
  }
}

export function normalizeLocationLocalDateString(dateStr) {
  if (!dateStr || typeof dateStr !== "string") return null;

  // Split date by hyphen or slash
  const parts = dateStr.trim().split(/[-/]/);
  if (parts.length !== 3) return dateStr;

  let year, month, day;

  if (parts[0].length === 4) {
    // Already YYYY-MM-DD
    [year, month, day] = parts;
  } else {
    // DD-MM-YYYY -> Convert to YYYY-MM-DD
    [day, month, year] = parts;
  }

  // Ensure 2-digit padding for month and day
  const formattedMonth = String(month).padStart(2, "0");
  const formattedDay = String(day).padStart(2, "0");

  return `${year}-${formattedMonth}-${formattedDay}`;
}
