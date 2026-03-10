// passport.js
import pkg from "passport-local";
const LocalStrategy = pkg.Strategy;
import bcrypt from "bcrypt";
import pool from "./db.js";

const configurePassport = (passport) => {

  // TENANT LOGIN STRATEGY (checks tenant_users → temp_tenant_users)
  passport.use(
    "tenant-local",
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          // 1️⃣ Check main tenant_users table
          let result = await pool.query(
            `SELECT t.*, e.name as estate_name 
            FROM tenant_users t
            JOIN estates e ON t.estate_id = e.id
            WHERE t.email = $1`,
            [email]
          );

          let user = result.rows[0];

          if (!user) {
            const tempResult = await pool.query(
              "SELECT * FROM temp_tenant_users WHERE email = $1",
              [email]
            );
            user = tempResult.rows[0];

            if (user) {
              user.isTemp = true; 
            }
          }

          if (!user) {
            return done(null, false, { message: "Tenant not found" });
          }

          const match = await bcrypt.compare(password, user.password);
          if (!match) {
            return done(null, false, { message: "Incorrect password" });
          }

          if (!user.isTemp && user.first_login) {
            console.log(`✨ First login for tenant: ${user.name}`);

            try {
              await pool.query(
                "UPDATE tenant_users SET first_login = FALSE WHERE id = $1",
                [user.id]
              );

              user.showWelcome = true;
            } catch (dbErr) {
              console.error("Error updating first_login flag:", dbErr);
            }
          }

          return done(null, user);

        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // ESTATE ADMIN LOGIN STRATEGY
  passport.use(
    "admin-local",
    new LocalStrategy(
      { usernameField: "email" },
      async (email, password, done) => {
        try {
          const result = await pool.query(
            "SELECT * FROM estate_admin_users WHERE email = $1",
            [email]
          );

          const user = result.rows[0];
          if (!user) return done(null, false, { message: "Admin not found" });

          const match = await bcrypt.compare(password, user.password);
          if (!match) return done(null, false, { message: "Incorrect password" });

          return done(null, user);

        } catch (err) {
          return done(err);
        }
      }
    )
  );

  // SESSION SERIALIZE
  passport.serializeUser((user, done) => {
    let type = "ADMIN";
  
    if (user.isTemp || user.unit) {
      type = "TENANT";
    }
    
    done(null, {
      id: user.id,
      type: type,
      isTemp: user.isTemp || false
    });
  });

// SESSION DESERIALIZE
passport.deserializeUser(async (user, done) => {
  try {
    let result;

    if (user.type === "TENANT") {
      if (user.isTemp) {
        // Temp users don't have an estate_id yet, they have estate_id in join_requests
        // but for simplicity, we just fetch the user
        result = await pool.query(
          "SELECT * FROM temp_tenant_users WHERE id = $1",
          [user.id]
        );
      } else {
        // 🚀 JOIN with estates for permanent tenants
        result = await pool.query(
          `SELECT t.*, e.name as estate_name 
           FROM tenant_users t
           JOIN estates e ON t.estate_id = e.id
           WHERE t.id = $1`,
          [user.id]
        );
      }
    } else {
      // ADMINS
      result = await pool.query(
        "SELECT * FROM estate_admin_users WHERE id = $1",
        [user.id]
      );
    }

    if (!result.rows[0]) {
      return done(null, false);
    }

    // Mark as temp if necessary
    const finalUser = result.rows[0];
    if (user.isTemp) finalUser.isTemp = true;

    done(null, finalUser);
  } catch (err) {
    done(err);
  }
});

};

export default configurePassport;
