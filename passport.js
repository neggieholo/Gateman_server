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
            "SELECT * FROM tenant_users WHERE email = $1",
            [email]
          );

          let user = result.rows[0];

          // 2️⃣ If not found → check temp_tenant_users
          if (!user) {
            const tempResult = await pool.query(
              "SELECT * FROM temp_tenant_users WHERE email = $1",
              [email]
            );
            user = tempResult.rows[0];

            if (user) {
              user.isTemp = true; // mark user as temp
            }
          }

          // 3️⃣ If no user anywhere → fail
          if (!user) {
            return done(null, false, { message: "Tenant not found" });
          }

          // 4️⃣ Password check
          const match = await bcrypt.compare(password, user.password);
          if (!match) {
            return done(null, false, { message: "Incorrect password" });
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
    done(null, {
      id: user.id,
      type: user.unit ? "TENANT" : "ADMIN",
      isTemp: user.isTemp || false
    });
  });

  // SESSION DESERIALIZE
  passport.deserializeUser(async (user, done) => {
  try {
    let table;

    if (user.type === "TENANT") {
      table = user.isTemp ? "temp_tenant_users" : "tenant_users";
    } else {
      table = "estate_admin_users";
    }

    const result = await pool.query(
      `SELECT * FROM ${table} WHERE id = $1`,
      [user.id]
    );

    if (!result.rows[0]) {
      // User not found → invalidate session
      return done(null, false);
    }

    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

};

// ✅ Export as ES module
export default configurePassport;
