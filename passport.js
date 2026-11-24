// passport.js
import pkg from "passport-local";
const LocalStrategy = pkg.Strategy;
import bcrypt from "bcrypt";
import pool from "./db.js";

const configurePassport = (passport) => {
  passport.use(
    "admin-local",
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          const compareEmail = email.toLowerCase();

          const result = await pool.query(
            `SELECT 
             *
           FROM estate_admin_users
           WHERE LOWER(email) = $1`,
            [compareEmail],
          );

          const user = result.rows[0];
          if (!user) return done(null, false, { message: "User not found" });

          const match = await bcrypt.compare(password, user.password);
          if (!match)
            return done(null, false, { message: "Incorrect password" });

          if (user.estate_ids && user.estate_ids.length > 0) {
            const estatesResult = await pool.query(
              `SELECT id, name as estate_name, estate_code, street_address, state, lga, town, plan, payment_items, bank_name, bank_code, bank_account_number, bank_account_name, emergency_contacts, payment_type, external_api_url, subscription_expiry , created_at
                 FROM estates 
                 WHERE id = ANY($1::uuid[])`,
              [user.estate_ids],
            );
            user.estates = estatesResult.rows;
          } else {
            user.estates = [];
          }

          // Auto-verify email and phone upon successful initial login
          if (user.is_first_login) {
            console.log(`✨ First login processing for admin: ${user.name}`);
            try {
              await pool.query(
                `UPDATE estate_admin_users 
                   SET is_first_login = FALSE,
                   email_verified = TRUE,
                   phone_verified = CASE WHEN phone_number IS NOT NULL AND phone_number != '' THEN TRUE ELSE phone_verified END
               WHERE id = $1`,
                [user.id],
              );

              user.is_first_login = true;
              user.email_verified = true;
              if (user.phone_number) user.phone_verified = true;
            } catch (dbErr) {
              console.error(
                "Error processing admin first_login onboarding:",
                dbErr,
              );
            }
          }

          const root_admin_result = await pool.query(
            `SELECT * FROM estates WHERE LOWER(root_admin_email) = $1`,
            [compareEmail],
          );

          if (root_admin_result.rows.length > 0) {
            user.is_root_admin = true;
          }

          return done(null, user);
        } catch (err) {
          return done(err);
        }
      },
    ),
  );

  // RESIDENT LOGIN
  passport.use(
    "tenant-local",
    new LocalStrategy(
      { usernameField: "email", passReqToCallback: true },
      async (req, email, password, done) => {
        const compareEmail = email.toLowerCase();
        try {
          const isBiometric = req.body.biometric_login === true;

          // Step A: Fetch base permanent tenant details
          let result = await pool.query(
            "SELECT * FROM tenant_users WHERE LOWER(email) = $1",
            [compareEmail],
          );

          let user = result.rows[0];

          // Step B: If not found, look up temp tenants
          if (!user) {
            const tempResult = await pool.query(
              "SELECT * FROM temp_tenant_users WHERE LOWER(email) = $1",
              [compareEmail],
            );
            user = tempResult.rows[0];
            if (user) user.isTemp = true;
          }

          if (!user) {
            return done(null, false, { message: "Tenant not found" });
          }

          if (isBiometric && user.password_changed) {
            return done(null, false, { message: "PASSWORD_CHANGED" });
          }

          let match = await bcrypt.compare(password, user.password);

          if (!match && user.temp_password) {
            match = await bcrypt.compare(password, user.temp_password);
            if (match) {
              user.isTempPassword = true;
            }
          }

          if (!match) {
            return done(null, false, { message: "Incorrect password" });
          }

          // Step C: If permanent user, aggregate all their estate profiles
          if (!user.isTemp) {
            if (user.estate_ids && user.estate_ids.length > 0) {
              const estatesResult = await pool.query(
                `SELECT id, name, street_address, state, lga, town, plan, subscription_expiry 
                 FROM estates 
                 WHERE id = ANY($1::uuid[])`,
                [user.estate_ids],
              );
              user.estates = estatesResult.rows;
            } else {
              user.estates = [];
            }
            if (user.first_login) {
              console.log(`✨ First login processing for tenant: ${user.name}`);
              try {
                await pool.query(
                  `UPDATE tenant_users 
                   SET first_login = FALSE
                   WHERE id = $1`,
                  [user.id],
                );

                user.first_login = true;
                user.showWelcome = true;

                // 2. Clear temp tenant record for main account registrations
                if (!user.parent_account_id) {
                  await pool.query(
                    "DELETE FROM temp_tenant_users WHERE LOWER(email) = $1",
                    [compareEmail],
                  );
                }
              } catch (dbErr) {
                console.error(
                  "Error processing first_login onboarding:",
                  dbErr,
                );
              }
            }
          }

          if (!isBiometric && user.password_changed) {
            await pool.query(
              "UPDATE tenant_users SET password_changed = FALSE WHERE id = $1",
              [user.id],
            );
          }

          return done(null, user);
        } catch (err) {
          return done(err);
        }
      },
    ),
  );

  // SECURITY LOGIN
  passport.use(
    "security-local",
    new LocalStrategy(
      { usernameField: "email", passReqToCallback: true },
      async (req, email, password, done) => {
        try {
          const compareEmail = email.toLowerCase();
          const isBiometric = req.body.biometric_login === true;
          let result = await pool.query(
            `SELECT * 
             FROM security_users
             WHERE LOWER(email) = $1`,
            [compareEmail],
          );

          let user = result.rows[0];

          if (!user) {
            const tempResult = await pool.query(
              "SELECT * FROM temp_security_users WHERE LOWER(email) = $1",
              [compareEmail],
            );
            user = tempResult.rows[0];
            if (user) user.isTemp = true;
          }

          if (!user) {
            return done(null, false, { message: "Security user not found" });
          }

          if (isBiometric && user.password_changed) {
            return done(null, false, {
              message: "PASSWORD_CHANGED",
            });
          }
          
          // 3️⃣ Verify Password
          let match = await bcrypt.compare(password, user.password);

          if (!match && user.temp_password) {
            match = await bcrypt.compare(password, user.temp_password);
            if (match) {
              user.isTempPassword = true;
            }
          }
          if (!match) {
            return done(null, false, { message: "Incorrect password" });
          }

          if (!user.isTemp) {
            const estatesResult = await pool.query(
              `SELECT id, name, address, state, lga, town, plan, subscription_expiry 
                 FROM estates 
                 WHERE id = $1`,
              [user.estate_id],
            );
            user.estate = estatesResult.rows[0];

            if (user.first_login) {
              try {
                await pool.query(
                  "UPDATE security_users SET first_login = FALSE WHERE id = $1",
                  [user.id],
                );

                await pool.query(
                  "DELETE FROM temp_security_users WHERE LOWER(email) = $1",
                  [compareEmail],
                );

                user.showWelcome = true;
              } catch (dbErr) {
                console.error("Error updating first_login flag:", dbErr);
              }
            }
          }

          if (!isBiometric && user.password_changed) {
            await pool.query(
              "UPDATE security_users SET password_changed = FALSE WHERE id = $1",
              [user.id],
            );
          }

          return done(null, user);
        } catch (err) {
          return done(err);
        }
      },
    ),
  );

  // SUPER ADMIN LOGIN
  passport.use(
    "super-admin-local",
    new LocalStrategy(
      {
        usernameField: "email",
        passwordField: "password",
      },
      async (email, password, done) => {
        try {
          const result = await pool.query(
            "SELECT * FROM super_admins WHERE LOWER(email) = $1 AND is_active = true",
            [email.trim().toLowerCase()],
          );

          const admin = result.rows[0];

          // 1. Check if admin exists
          if (!admin) {
            return done(null, false, {
              message: "Access denied or account not found.",
            });
          }

          // 2. Verify Password
          const match = await bcrypt.compare(password, admin.password_hash);
          if (!match) {
            return done(null, false, {
              message: "Incorrect password.",
            });
          }

          // 3. First login onboarding adjustments & auto-verifications
          if (admin.is_first_login) {
            console.log(
              `✨ First login processing for super admin: ${admin.full_name}`,
            );
            try {
              await pool.query(
                `UPDATE super_admins 
                  SET is_first_login = FALSE,
                   email_verified = TRUE,
                   phone_verified = CASE WHEN phone_number IS NOT NULL AND phone_number != '' THEN TRUE ELSE phone_verified END,
                   last_login = NOW()
               WHERE id = $1`,
                [admin.id],
              );

              admin.is_first_login = true;
              admin.email_verified = true;
              if (admin.phone_number) admin.phone_verified = true;
            } catch (dbErr) {
              console.error(
                "Error updating super admin first_login flags:",
                dbErr,
              );
            }
          }

          return done(null, admin);
        } catch (err) {
          return done(err);
        }
      },
    ),
  );

  // SESSION SERIALIZE
  passport.serializeUser((user, done) => {
    done(null, {
      id: user.id,
      type: user.role,
      isTemp: user.isTemp || false,
      is_root_admin: user.is_root_admin || false,
    });
  });

  // SESSION DESERIALIZE
  passport.deserializeUser(async (user, done) => {
    try {
      let result;

      if (user.type === "SECURITY") {
        const query = user.isTemp
          ? `SELECT * FROM temp_security_users WHERE id = $1`
          : `SELECT * FROM security_users WHERE id = $1`;
        result = await pool.query(query, [user.id]);
      } else if (user.type === "TENANT") {
        // Drop joins here—fetch directly from the newly altered table structure
        const query = user.isTemp
          ? `SELECT * FROM temp_tenant_users WHERE id = $1`
          : `SELECT * FROM tenant_users WHERE id = $1`;
        result = await pool.query(query, [user.id]);
      } else if (user.type === "SUPER_ADMIN") {
        result = await pool.query("SELECT * FROM super_admins WHERE id = $1", [
          user.id,
        ]);
      } else if (user.type === "VENDOR") {
        result = await pool.query("SELECT * FROM vendors WHERE id = $1", [
          user.id,
        ]);
      } else {
        result = await pool.query(
          `SELECT *           
           FROM estate_admin_users 
           WHERE id = $1`,
          [user.id],
        );
      }

      if (!result.rows[0]) return done(null, false);

      const finalUser = result.rows[0];
      if (user.isTemp) finalUser.isTemp = true;
      if (user.is_root_admin) finalUser.is_root_admin = true;

      if (user.type === "SECURITY" && !finalUser.isTemp) {
        const estatesResult = await pool.query(
          `SELECT id, name, address, state, lga, town, plan, subscription_expiry 
                 FROM estates 
                 WHERE id = $1`,
          [finalUser.estate_id],
        );
        finalUser.estate = estatesResult.rows[0];
      }

      // Deep load complex array dependencies back into session state for permanent tenants
      if (user.type === "TENANT" && !finalUser.isTemp) {
        if (finalUser.estate_ids && finalUser.estate_ids.length > 0) {
          const estatesResult = await pool.query(
            `SELECT id, name, street_address, state, lga, town, plan, subscription_expiry
             FROM estates 
             WHERE id = ANY($1::uuid[])`,
            [finalUser.estate_ids],
          );
          finalUser.estates = estatesResult.rows;
        } else {
          finalUser.estates = [];
        }
      }

      if (user.type === "ADMIN") {
        if (finalUser.estate_ids && finalUser.estate_ids.length > 0) {
          const estatesResult = await pool.query(
            `SELECT id, name as estate_name, estate_code, street_address, state, lga, town,plan, payment_items, bank_name, bank_code, bank_account_number, bank_account_name, emergency_contacts, payment_type, external_api_url, subscription_expiry 
                 FROM estates 
                 WHERE id = ANY($1::uuid[])`,
            [finalUser.estate_ids],
          );
          finalUser.estates = estatesResult.rows;
        } else {
          finalUser.estates = [];
        }
      }

      done(null, finalUser);
    } catch (err) {
      done(err);
    }
  });
};

export default configurePassport;
