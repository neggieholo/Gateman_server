import express from "express";
import pool from "./db.js";
import { io } from "./server.js";
import multer from "multer";
import {
  isAuth,
  ensureAdmin,
  authorizeEstate,
  verifyPermission,
  verifyEstateSubscription,
  verifyPlanModule,
} from "./middlewares.js";
import { sendPushNotification } from "./invitations.js";
import bcrypt from "bcrypt";
import crypto from "crypto";
import { createAppAuditLog } from "./helpers.js";
import { sendTenantWelcomeEmail } from "./emailService.js";

const router = express.Router();

router.use(isAuth);

router.get("/accounts-details", async (req, res) => {
  const userId = req.user.id;

  try {
    const metaQuery = `SELECT estate_ids, sub_users FROM tenant_users WHERE id = $1`;
    const metaResult = await pool.query(metaQuery, [userId]);

    if (metaResult.rows.length === 0) {
      return res.status(404).json({ error: "User profile context not found" });
    }

    const { estate_ids, sub_users } = metaResult.rows[0];

    let estates = [];
    if (estate_ids && estate_ids.length > 0) {
      const estatesQuery = `
        SELECT id, name, estate_code, address, created_at, state, lga, town 
        FROM estates 
        WHERE id = ANY($1::uuid[])
      `;
      const estatesResult = await pool.query(estatesQuery, [estate_ids]);
      estates = estatesResult.rows;
    }

    let subUsers = [];
    if (sub_users && sub_users.length > 0) {
      const subUsersQuery = `
        SELECT id, estate_ids, name, email, phone, role, created_at, locations, avatar, biometric_login, password_changed
        FROM tenant_users 
        WHERE id = ANY($1::uuid[])
      `;
      const subUsersResult = await pool.query(subUsersQuery, [sub_users]);
      subUsers = subUsersResult.rows;
    }

    res.json({
      success: true,
      estates,
      subUsers,
    });
  } catch (err) {
    console.error("Workspace details fetch crash:", err);
    res.status(500).json({ error: "Failed to gather workspace metrics" });
  }
});

router.put("/chat-settings", async (req, res) => {
  try {
    const userId = req.user.id;
    const { read_receipts } = req.body;

    if (typeof read_receipts !== "boolean") {
      return res.status(400).json({ error: "Invalid read_receipts flag." });
    }

    const query = `
      UPDATE tenant_users 
      SET chat_settings = chat_settings || jsonb_build_object('read_receipts', $1::boolean)
      WHERE id = $2
      RETURNING chat_settings;
    `;

    const result = await pool.query(query, [read_receipts, userId]);

    if (result.rowCount === 0) {
      return res.status(404).json({ error: "User record not found." });
    }

    return res.status(200).json({
      success: true,
      chatSettings: result.rows[0].chat_settings,
    });
  } catch (error) {
    console.error("Error updating chat settings:", error);
    return res.status(500).json({ error: "Internal server error" });
  }
});

const storage = multer.memoryStorage();
const upload = multer({ storage });

router.post(
  "/dashboard-stats",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    const { id: resident_id } = req.user;
    const { estate_id } = req.body;
    const today = new Date().toISOString().split("T")[0];

    try {
      // 1. Fetch estate subscription plan to check enabled add-ons
      const planRes = await pool.query(
        "SELECT plan FROM estates WHERE id = $1",
        [estate_id],
      );

      const plan = planRes.rows[0]?.plan || {
        is_trial: false,
        selected_add_ons: [],
      };
      const isTrial = plan.is_trial;
      const addOns = plan.selected_add_ons || [];

      const isEnabled = (key) => isTrial || addOns.includes(key);

      // 2. Prepare conditional DB queries

      // Invitations belong to the core/security scope (always allowed or checked via security add-on)
      const invitePromise = isEnabled("security")
        ? pool.query(
            `SELECT 
               COUNT(*) FILTER (WHERE actual_checkin_date = CURRENT_DATE) as checked_in,
               COUNT(*) FILTER (WHERE actual_checkout_date = CURRENT_DATE) as checked_out,
               COUNT(*) FILTER (
                 WHERE (start_date <= CURRENT_DATE AND end_date >= CURRENT_DATE)
                 AND is_cancelled = false
                 AND NOT (excluded_dates @> $3::jsonb)
               ) as total_expected_invites,
               COUNT(*) FILTER (
                 WHERE actual_checkin_date = CURRENT_DATE 
                 AND actual_checkout_time IS NULL 
                 AND end_time < CURRENT_TIME
               ) as overstayed
             FROM invitations 
             WHERE estate_id = $1 AND resident_id = $2;`,
            [estate_id, resident_id, JSON.stringify(today)],
          )
        : Promise.resolve(null);

      // Facility Bookings / Events module check
      const bookingPromise = isEnabled("facility_bookings")
        ? pool.query(
            `SELECT 
         lb.venue_name,
         slot->>'date' as slot_date,
         slot->>'start_time' as slot_start_time,
         slot->>'end_time' as slot_end_time,
         TO_DATE(slot->>'date', 'DD-MM-YYYY') as parsed_date
       FROM location_bookings lb
       CROSS JOIN LATERAL jsonb_array_elements(lb.booked_dates) AS slot
       WHERE lb.estate_id = $1 
         AND lb.resident_id = $2
         AND lb.end_date >= CURRENT_DATE
         AND lb.status = 'APPROVED'
         AND (TO_DATE(slot->>'date', 'DD-MM-YYYY') + (slot->>'end_time')::TIME)::TIMESTAMPTZ > NOW()
       ORDER BY parsed_date ASC, slot_start_time ASC;`,
            [estate_id, resident_id],
          )
        : Promise.resolve(null);

      // Community / Social Feed module check
      const socialPromise = isEnabled("community")
        ? pool.query(
            `SELECT 
               (
                 SELECT COUNT(*) 
                 FROM posts 
                 WHERE estate_id = $1 
                   AND is_archived = false 
                   AND created_at > COALESCE((tu.last_post_read->>$1)::timestamptz, '1970-01-01'::timestamptz)
               ) as unread_posts_count,
               
               (
                 SELECT COUNT(*) 
                 FROM likes l
                 JOIN posts p ON l.post_id = p.id
                 WHERE p.author_id = $2 
                   AND p.estate_id = $1
                   AND p.is_archived = false
                   AND l.created_at > COALESCE((tu.last_post_read->>$1)::timestamptz, '1970-01-01'::timestamptz)
                   AND l.user_id != $2
               ) as new_likes_count,
               
               (
                 SELECT COUNT(*) 
                 FROM comments c
                 JOIN posts p ON c.post_id = p.id
                 WHERE p.author_id = $2 
                   AND p.estate_id = $1
                   AND p.is_archived = false
                   AND c.created_at > COALESCE((tu.last_post_read->>$1)::timestamptz, '1970-01-01'::timestamptz)
                   AND c.user_id != $2
               ) as new_comments_count
             FROM tenant_users tu
             WHERE tu.id = $2;`,
            [estate_id, resident_id],
          )
        : Promise.resolve(null);

      // 3. Run queries concurrently
      const [inviteRes, bookingRes, socialRes] = await Promise.all([
        invitePromise,
        bookingPromise,
        socialPromise,
      ]);

      const invites = inviteRes?.rows[0];
      const social = socialRes?.rows[0];

      // Format bookings if enabled
      const mappedBookings = bookingRes
        ? bookingRes.rows.map((row) => {
            // Convert "DD-MM-YYYY" into standard "YYYY-MM-DD" expected by frontend UI
            const [day, month, year] = row.slot_date.split("-");
            const formattedStartDate = `${year}-${month}-${day}`;

            return {
              venue: row.venue_name || "Unknown Venue",
              start_date: formattedStartDate,
              start_time: row.slot_start_time,
              end_time: row.slot_end_time,
            };
          })
        : [];

      // 4. Return formatted response with zero/empty fallbacks
      res.json({
        success: true,
        stats: {
          invitations: invites
            ? {
                total_expected: parseInt(invites.total_expected_invites) || 0,
                checked_in: parseInt(invites.checked_in) || 0,
                checked_out: parseInt(invites.checked_out) || 0,
                overstayed: parseInt(invites.overstayed) || 0,
              }
            : {
                total_expected: 0,
                checked_in: 0,
                checked_out: 0,
                overstayed: 0,
              },
          bookings: mappedBookings,
          feed: social
            ? {
                unread_posts: parseInt(social.unread_posts_count) || 0,
                likes_on_my_posts: parseInt(social.new_likes_count) || 0,
                comments_on_my_posts: parseInt(social.new_comments_count) || 0,
              }
            : {
                unread_posts: 0,
                likes_on_my_posts: 0,
                comments_on_my_posts: 0,
              },
        },
      });
    } catch (err) {
      console.error("Resident Dashboard Sync Error:", err);
      res.status(500).json({ error: "Resident dashboard sync failed" });
    }
  },
);

router.post(
  "/create-subuser",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    const primaryTenantId = req.user.id;
    const { name, email, phone_number, locations, estateId } = req.body;
    const selfieUrl = req.body.selfie || null;

    try {
      if (req.user.parent_account_id) {
        return res.status(403).json({
          error:
            "Access Denied. Sub-accounts are not authorized to provision additional sub-users.",
        });
      }

      await pool.query("BEGIN");

      const sanitizedEmail = email.toLowerCase().trim();
      const emailCheckQuery = `
      SELECT id FROM tenant_users WHERE LOWER(email) = $1
      UNION
      SELECT id FROM temp_tenant_users WHERE LOWER(email) = $1;
    `;

      const phoneCheckQuery = `
      SELECT id FROM tenant_users WHERE phone = $1
      UNION
      SELECT id FROM temp_tenant_users WHERE phone = $1;
    `;
      const emailCheck = await pool.query(emailCheckQuery, [sanitizedEmail]);
      const phoneCheck = await pool.query(phoneCheckQuery, [
        phoneCheckQuery.trim(),
      ]);

      if (emailCheck.rows.length > 0) {
        await pool.query("ROLLBACK");
        return res.status(409).json({
          error: "An account with this email address already exists.",
        });
      }

      if (phoneCheck.rows.length > 0) {
        await pool.query("ROLLBACK");
        return res.status(409).json({
          error: "An account with this phone number already exists.",
        });
      }

      const tenantCheck = await pool.query(
        `SELECT sub_users FROM tenant_users WHERE id = $1`,
        [primaryTenantId],
      );

      if (tenantCheck.rows.length === 0) {
        await pool.query("ROLLBACK");
        return res
          .status(404)
          .json({ error: "Primary tenant account record not found." });
      }

      const max_subs = 4

      const currentSubUsers = tenantCheck.rows[0].sub_users || [];
      if (currentSubUsers.length >= max_subs) {
        await pool.query("ROLLBACK");
        return res.status(400).json({
          error:
            `Sub-account limit reached. You are only allowed a maximum of ${max_subs} sub-accounts.`,
        });
      }

      const estateIdsArray = [estateId];
      const locationsJsonb =
        typeof locations === "string" ? JSON.parse(locations) : locations;
      const formattedLocationsObj = { [estateId]: locationsJsonb };

      // 💡 Format avatar as JSON object mapping estateId -> avatar URL
      const avatarObj = selfieUrl ? { [estateId]: selfieUrl } : null;

      // 🔑 Generate secure password parts internally on backend
      const emailPasswordPart = crypto.randomBytes(3).toString("hex");
      const smsPasswordPart = "gate";
      const fullCombinedPassword = emailPasswordPart + smsPasswordPart;

      const passwordHash = await bcrypt.hash(fullCombinedPassword, 10);

      const subUserInsertQuery = `
      INSERT INTO tenant_users (
        name, email, phone, password, role, estate_ids, locations, avatar, parent_account_id, first_login
      )
      VALUES ($1, $2, $3, $4, 'TENANT', $5, $6, $7, $8, true)
      RETURNING id, name, email, phone, role, estate_ids, locations, avatar, parent_account_id, first_login;
    `;

      // ✅ FIXED: All 8 arguments matched correctly to $1 through $8
      const newSubUserRes = await pool.query(subUserInsertQuery, [
        name.trim(), // $1
        sanitizedEmail, // $2
        phone_number ? phone_number.trim() : null, // $3
        passwordHash, // $4
        estateIdsArray, // $5
        JSON.stringify(formattedLocationsObj), // $6
        avatarObj ? JSON.stringify(avatarObj) : null, // $7 (Valid JSON string for JSONB avatar column)
        primaryTenantId, // $8
      ]);

      const newSubUser = newSubUserRes.rows[0];

      await pool.query(
        `UPDATE tenant_users 
       SET sub_users = array_append(coalesce(sub_users, ARRAY[]::UUID[]), $1::UUID) 
       WHERE id = $2`,
        [newSubUser.id, primaryTenantId],
      );

      await pool.query("COMMIT");

      // ✉️ Dispatch credentials asynchronously based on presence of phone number
      if (phone_number) {
        try {
          await sendTenantWelcomeEmail(
            sanitizedEmail,
            name.trim(),
            emailPasswordPart,
            true,
          );
          console.log(
            `Sub-user email credential part dispatched to ${sanitizedEmail}`,
          );
        } catch (mailErr) {
          console.error("⚠️ Background email dispatch failed:", mailErr);
        }

        console.log(
          `[TEST MODE SMS TOKEN SIMULATION] Phone: ${phone_number} | Token: ${smsPasswordPart}`,
        );
      } else {
        try {
          await sendTenantWelcomeEmail(
            sanitizedEmail,
            name.trim(),
            fullCombinedPassword,
            true,
          );
          console.log(
            `Full sub-user email credentials dispatched to ${sanitizedEmail}`,
          );
        } catch (mailErr) {
          console.error("⚠️ Background email dispatch failed:", mailErr);
        }
      }

      // 1. Respond to client instantly
      res.status(201).json({
        success: true,
        message: `Sub-account for ${newSubUser.name} provisioned successfully.`,
        subUser: newSubUser,
      });

      // 2. Log identity provisioning asynchronously
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "SUBUSER_PROFILE_CREATED",
        target_resource: "tenant_users",
        target_id: newSubUser.id,
        description: `Primary tenant provisioned secondary sub-account credentials for family member/co-resident "${newSubUser.name}".`,
        state_before: null,
        state_after: newSubUser,
        urgency: "HIGH",
      });
    } catch (err) {
      await pool.query("ROLLBACK").catch(() => {});
      console.error("Sub-user Provisioning Error:", err);
      res
        .status(500)
        .json({ error: "Failed to allocate sub-account profile registry." });
    }
  },
);

router.delete(
  "/delete-subuser/:subUserId",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    console.log("Deleting subuser");
    const { subUserId } = req.params;
    const primaryTenantId = req.user.id;
    const estateId = req.query.estate_id;
    console.log("Subuser Id:", subUserId, "Estate id:", estateId);

    try {
      if (req.user.parent_account_id) {
        return res.status(403).json({
          error:
            "Access Denied. Sub-accounts are not authorized to delete profiles.",
        });
      }

      // Fetch profile details BEFORE executing hard delete to populate log state mirrors
      const subUserCheck = await pool.query(
        `SELECT id, name, email, role, estate_ids, locations, parent_account_id 
         FROM tenant_users WHERE id = $1 AND parent_account_id = $2`,
        [subUserId, primaryTenantId],
      );

      if (subUserCheck.rows.length === 0) {
        return res.status(404).json({
          error: "Sub-user profile not found or unattached to your account.",
        });
      }

      const subUserDataBefore = subUserCheck.rows[0];

      await pool.query("BEGIN");

      await pool.query(
        `UPDATE tenant_users SET sub_users = array_remove(sub_users, $1::UUID) WHERE id = $2`,
        [subUserId, primaryTenantId],
      );

      // ✅ FIX: Changed `id` to `subUserId`
      await pool.query(
        "DELETE FROM invitations WHERE estate_id = $1 AND resident_id = $2",
        [estateId, subUserId],
      );
      await pool.query(
        "DELETE FROM location_bookings WHERE estate_id = $1 AND resident_id = $2",
        [estateId, subUserId],
      );
      await pool.query(
        "DELETE FROM estate_reports WHERE estate_id = $1 AND reporter_id = $2",
        [estateId, subUserId],
      );
      await pool.query(
        "DELETE FROM service_requests WHERE estate_id = $1 AND resident_id = $2",
        [estateId, subUserId],
      );
      await pool.query(
        "DELETE FROM posts WHERE estate_id = $1 AND author_id = $2",
        [estateId, subUserId],
      );
      await pool.query(
        "DELETE FROM payment_logs WHERE estate_id = $1 AND resident_id = $2",
        [estateId, subUserId],
      );

      await pool.query(`DELETE FROM tenant_users WHERE id = $1`, [subUserId]);
      await pool.query("COMMIT");

      // 1. Respond to client instantly
      res.json({ success: true, message: "Sub-account deleted successfully." });

      // 2. Track identity destruction asynchronously
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "SUBUSER_PROFILE_DELETED",
        target_resource: "tenant_users",
        target_id: subUserId,
        description: `Primary tenant permanently deleted sub-account profile belonging to "${subUserDataBefore.name}".`,
        state_before: subUserDataBefore,
        state_after: null,
        urgency: "HIGH",
      });
    } catch (err) {
      await pool.query("ROLLBACK").catch(() => {});
      console.error("Delete Sub-User Error:", err);
      res
        .status(500)
        .json({ error: "Internal server error performing removal operation." });
    }
  },
);

// -------------------- TENANT SELF-SERVICE LEAVE ESTATE (LOGGED) --------------------
router.delete(
  "/leave-estate/:estateId",
  authorizeEstate,
  verifyEstateSubscription,
  async (req, res) => {
    const { estateId } = req.params;
    const primaryTenantId = req.user.id;

    try {
      if (req.user.parent_account_id) {
        return res.status(403).json({
          error:
            "Access Denied. Sub-accounts cannot alter estate linkages directly.",
        });
      }

      // Fetch current snapshot prior to stripping connection boundaries
      const tenantRes = await pool.query(
        `SELECT * FROM tenant_users WHERE id = $1`,
        [primaryTenantId],
      );

      if (tenantRes.rows.length === 0) {
        return res
          .status(404)
          .json({ error: "Tenant account profile record not found." });
      }

      const tenant = tenantRes.rows[0];
      const currentEstateIds = tenant.estate_ids || [];

      const currentLocationsMap =
        typeof tenant.locations === "string"
          ? JSON.parse(tenant.locations)
          : tenant.locations || {};

      if (!currentEstateIds.includes(estateId)) {
        return res
          .status(400)
          .json({ error: "You are not connected to this estate scope." });
      }

      await pool.query("BEGIN");

      // --- CLEANUP RESIDENT ESTATE ACTIVITY ---
      await pool.query(
        "DELETE FROM invitations WHERE estate_id = $1 AND resident_id = $2",
        [estateId, primaryTenantId],
      );
      await pool.query(
        "DELETE FROM location_bookings WHERE estate_id = $1 AND resident_id = $2",
        [estateId, primaryTenantId],
      );
      await pool.query(
        "DELETE FROM estate_reports WHERE estate_id = $1 AND reporter_id = $2",
        [estateId, primaryTenantId],
      );
      await pool.query(
        "DELETE FROM service_requests WHERE estate_id = $1 AND resident_id = $2",
        [estateId, primaryTenantId],
      );
      await pool.query(
        "DELETE FROM posts WHERE estate_id = $1 AND author_id = $2",
        [estateId, primaryTenantId],
      );
      await pool.query(
        "DELETE FROM payment_logs WHERE estate_id = $1 AND resident_id = $2",
        [estateId, primaryTenantId],
      );

      // --- HANDLE SUB-USERS DELETION ---
      const subUserIds = tenant.sub_users || [];
      let remainingSubUserIds = [...subUserIds];

      if (subUserIds.length > 0) {
        // Fetch sub-users tied to this specific estate
        const subUsersToPurgeRes = await pool.query(
          `SELECT id FROM tenant_users 
           WHERE id = ANY($1::uuid[]) AND $2 = ANY(estate_ids)`,
          [subUserIds, estateId],
        );

        const idsToDelete = subUsersToPurgeRes.rows.map((row) => row.id);

        if (idsToDelete.length > 0) {
          // Clean up records for sub-users attached to this estate
          await pool.query(
            "DELETE FROM invitations WHERE estate_id = $1 AND resident_id = ANY($2::uuid[])",
            [estateId, idsToDelete],
          );
          await pool.query(
            "DELETE FROM location_bookings WHERE estate_id = $1 AND resident_id = ANY($2::uuid[])",
            [estateId, idsToDelete],
          );
          await pool.query(
            "DELETE FROM estate_reports WHERE estate_id = $1 AND reporter_id = ANY($2::uuid[])",
            [estateId, idsToDelete],
          );
          await pool.query(
            "DELETE FROM service_requests WHERE estate_id = $1 AND resident_id = ANY($2::uuid[])",
            [estateId, idsToDelete],
          );
          await pool.query(
            "DELETE FROM posts WHERE estate_id = $1 AND author_id = ANY($2::uuid[])",
            [estateId, idsToDelete],
          );
          await pool.query(
            "DELETE FROM payment_logs WHERE estate_id = $1 AND resident_id = ANY($2::uuid[])",
            [estateId, idsToDelete],
          );

          // Permanently purge sub-accounts for this estate
          await pool.query(
            `DELETE FROM tenant_users WHERE id = ANY($1::uuid[])`,
            [idsToDelete],
          );

          remainingSubUserIds = subUserIds.filter(
            (id) => !idsToDelete.includes(id),
          );
        }
      }

      // --- UPDATE OR TEMPS RELOCATION ---
      const remainingEstateIds = currentEstateIds.filter(
        (id) => id !== estateId,
      );
      const locationsSnapshotBefore = { ...currentLocationsMap };
      delete currentLocationsMap[estateId];

      const { password: _p, ...safeTenantStateBefore } = tenant;

      if (remainingEstateIds.length === 0) {
        // Fetch estate name for feedback message
        const estateRes = await pool.query(
          "SELECT name FROM estates WHERE id = $1",
          [estateId],
        );
        const estate_name = estateRes.rows[0]?.name || "Estate Scope";

        const feedbackObj = JSON.stringify({
          type: "decline",
          estate: estate_name,
          message:
            "You have voluntarily left this estate domain. Account relocated to temporary status.",
        });

        // Relocate tenant to temp_tenant_users table
        await pool.query(
          `INSERT INTO temp_tenant_users 
           (name, email, password, phone, role, rejection_message, is_read)
           VALUES ($1, $2, $3, $4, $5, $6, FALSE)`,
          [
            tenant.name,
            tenant.email,
            tenant.password,
            tenant.phone,
            tenant.role || "TENANT",
            feedbackObj,
          ],
        );

        // Delete primary record from active tenant_users
        await pool.query("DELETE FROM tenant_users WHERE id = $1", [
          primaryTenantId,
        ]);
      } else {
        // Update remaining estates, locations, and sub_users
        await pool.query(
          `UPDATE tenant_users 
           SET estate_ids = $1, locations = $2, sub_users = $3 
           WHERE id = $4`,
          [
            remainingEstateIds,
            JSON.stringify(currentLocationsMap),
            remainingSubUserIds,
            primaryTenantId,
          ],
        );
      }

      // --- ADMIN NOTIFICATION LOGIC ---
      const adminResult = await pool.query(
        `SELECT eau.id 
         FROM estate_admin_users eau
         JOIN estates e ON e.root_admin_email = eau.email
         WHERE e.id = $1 
         LIMIT 1`,
        [estateId],
      );

      let adminNotification = null;
      if (adminResult.rows.length > 0) {
        const rootAdminId = adminResult.rows[0].id;
        const alertTitle = "Resident Departed 🚪";
        const alertBody = `Resident "${tenant.name}" (${tenant.email}) has left the estate scope along with their sub-account(s).`;

        const notifRes = await pool.query(
          `INSERT INTO notifications (estate_id, user_id, recipient_role, title, message, type) 
           VALUES ($1, $2, 'admin', $3, $4, 'general')
           RETURNING *`,
          [estateId, rootAdminId, alertTitle, alertBody],
        );

        adminNotification = notifRes.rows[0];
      }

      await pool.query("COMMIT");

      // Broadcast socket event to all connected estate admins
      if (adminNotification) {
        const adminRoom = `admins_estate_${estateId}`;
        io.to(adminRoom).emit("new_notification", adminNotification);
      }

      // Send response to client
      res.json({
        success: true,
        message:
          remainingEstateIds.length === 0
            ? "Successfully left the estate. Account moved to temporary holdings as no other estates remain."
            : "Successfully severed connection with this estate domain.",
      });

      // Audit Log
      await createAppAuditLog(req, {
        estate_id: estateId,
        action_type: "TENANT_SELF_REVOCATION_LEAVE",
        target_resource: "tenant_users",
        target_id: primaryTenantId,
        description: `Resident "${tenant.name}" triggered a self-service exit from estate scope.`,
        state_before: safeTenantStateBefore,
        state_after:
          remainingEstateIds.length === 0
            ? { status: "moved_to_temp_holdings", estate_id: estateId }
            : {
                id: tenant.id,
                estate_ids: remainingEstateIds,
                locations: currentLocationsMap,
                sub_users: remainingSubUserIds,
              },
        urgency: "HIGH",
      });
    } catch (err) {
      await pool.query("ROLLBACK").catch(() => {});
      console.error("Leave Estate Processing Error:", err);
      res.status(500).json({
        error:
          "Internal server framework database error leaving estate layout.",
      });
    }
  },
);

export default router;
