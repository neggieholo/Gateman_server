import express from "express";
import session from "express-session";
import passport from "passport";
import configurePassport from "./passport.js";
import connectPgSimple from "connect-pg-simple";
import pool from "./db.js";
import dotenv from "dotenv";
import cors from "cors";
import authRoute from "./auth.js";
import paymentRoute from "./payment.js";
import processRoute from "./tenantManagement.js";
import billsRoute from "./bills.js"
import invoicesRoute from "./invoices.js"
import { createServer } from "http";
import { Server } from "socket.io";
import firebaseAdmin from "./firebase.js";
import communityRoute from './community.js'
import invitationsRoute from './invitations.js';
import securityRoute from './securityManagement.js'
import NotificationsRoute from './Notifications.js'
import KYCRoute from './AdminKYC.js'
import SuperAdminRoute from './super_admin.js'
import crypto from "crypto";
import { sendPasswordResetCode } from "./emailService.js";
import { checkOverstays } from './invitations.js';
import bcrypt from "bcrypt";


dotenv.config();


const allowedOrigins = [
  "https:/gatemanhq.com", 
  "http://localhost:3005", 
  "http://localhost:3000", 
  "http://localhost:8081" 
];

const app = express();
const httpServer = createServer(app); // Wrap the app
const io = new Server(httpServer, {
  path: '/api/socket.io',
  cors: {
    origin: allowedOrigins,
    credentials: true
  }
});
const PgSession = connectPgSimple(session);

const sessionMiddleware = session({
  store: new PgSession({
    pool,
    pruneSessionInterval: 60,
    createTableIfMissing: true,
  }),
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  name: 'gateman.sid',
  cookie: {
    httpOnly: true,
    secure: process.env.NODE_ENV === "production",
    sameSite: "lax",
    path: "/",
    maxAge: 1000 * 60 * 60 * 24,
  },
});

app.use(sessionMiddleware);
app.use(express.json());
app.use(cors({
    origin: allowedOrigins,
    credentials: true              
}));


app.use(passport.initialize());
app.use(passport.session());
configurePassport(passport);

// app.use((req, res, next) => {
//     console.log("--- 🕵️ Session Check ---");
//     console.log("Cookies found:", req.headers.cookie); // See the raw string
//     console.log("Session ID:", req.sessionID);
//     console.log("User in Session:", req.session?.passport?.user);
//     console.log("Is Authenticated:", req.isAuthenticated());
//     console.log("-----------------------");
//     next();
// });
app.use("/api/auth", authRoute);
app.use("/api/payment", paymentRoute);
app.use("/api/admin", processRoute);
app.use("/api/bills", billsRoute);
app.use("/api/invoices", invoicesRoute);
app.use("/api/community", communityRoute);
app.use("/api/invitations", invitationsRoute);
app.use("/api/security", securityRoute);
app.use("/api/notifications", NotificationsRoute);
app.use("/api/kyc", KYCRoute);
app.use("/api/master", SuperAdminRoute);

app.get("/api/session-check", (req, res) => {
    if (req.isAuthenticated && req.isAuthenticated()) {
        res.json({ success: true, user: req.user});
    } else {
        res.status(401).json({ success: false });
    }
});

app.get("/api/auth/user", (req, res) => {
    // console.log('auth check');
    if (!req.user) return res.status(401).json({ error: "Not authenticated" });

    // console.log(req.user);
    res.json({
        id: req.user.id,
        name: req.user.name,
        email: req.user.email,
        photo: req.user.photo,
        total_tasks: req.user.total_tasks,
        completed_tasks: req.user.completed_tasks,
        provider: req.user.provider,
        preferences: req.user.preferences,
        timezone: req.user.timezone,
    });
});


// Logout
app.post("/api/logout", (req, res, next) => {
    req.logout((err) => {
        if (err) return next(err);

        req.session.destroy((err) => {
            if (err) return next(err);
            console.log("Session destroyed");

            res.clearCookie("gateman.sid");
            res.json({ message: "Logged out" });
        });
    });
});

app.post("/api/forgot-password", async (req, res) => {
    const { email, role } = req.body;
    console.log(`[Forgot Password] Request received for email: ${email}, role: ${role}`);

    if (!role || !email) {
        return res.status(400).json({ success: false, message: "Email and role are required" });
    }

    const cleanEmail = email.toLowerCase().trim();

    try {
        let tableName = "";
        let user = null;

        if (role === "admin") {
            tableName = "estate_admin_users";
            const result = await pool.query(`SELECT id, email FROM ${tableName} WHERE email = $1`, [cleanEmail]);
            user = result.rows[0];
        } 
        else if (role === "tenant") {
            // 1. Search primary tenants first
            const primarySearch = await pool.query(`SELECT id, email FROM tenant_users WHERE email = $1`, [cleanEmail]);
            
            if (primarySearch.rows.length > 0) {
                user = primarySearch.rows[0];
                tableName = "tenant_users";
            } else {
                // 2. Search temporary tenants if not found in primary
                const tempSearch = await pool.query(`SELECT id, email FROM temp_tenant_users WHERE email = $1`, [cleanEmail]);
                if (tempSearch.rows.length > 0) {
                    user = tempSearch.rows[0];
                    tableName = "temp_tenant_users";
                }
            }
        } else {
            return res.status(400).json({ success: false, message: "Invalid role provided" });
        }

        // If after checking the relevant tables we still have no user
        if (!user) {
            return res.json({ success: false, message: "Email not found" });
        }

        // Generate Secure Token
        const resetToken = crypto.randomBytes(32).toString("hex");
        const expiry = new Date(Date.now() + 3600000); // 1 hour

        // Update the specific table where the user was found
        await pool.query(
            `UPDATE ${tableName} SET reset_token = $1, reset_token_expiry = $2 WHERE id = $3`,
            [resetToken, expiry, user.id]
        );

        // Construct the link (keeping the specific table-role for the frontend reset page)
        const displayRole = tableName === "temp_tenant_users" ? "temp_tenant" : role;
        const resetLink = `http://localhost:3005/passwordReset/${displayRole}/${user.id}/${resetToken}`;

        const emailSent = await sendPasswordResetCode(cleanEmail, resetLink);

        if (emailSent) {
            return res.json({ 
                success: true, 
                message: "Reset link sent! Please check your email." 
            });
        } else {
            return res.status(500).json({ success: false, message: "Email service failed" });
        }

    } catch (error) {
        console.error("Forgot Password System Error:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

app.post("/api/reset-password", async (req, res) => {
    const { token, password, role, userId } = req.body;

    // 1. Validation
    if (!token || !password || !role || !userId) {
        return res.status(400).json({ success: false, message: "Missing required fields" });
    }

    try {
        // 2. Map the role to your specific PostgreSQL table names
        let tableName = "";
        if (role === "admin") {
            tableName = "estate_admin_users";
        } else if (role === "tenant") {
            tableName = "tenant_users";
        } else if (role === "temp_tenant") {
            tableName = "temp_tenant_users";
        } else {
            return res.status(400).json({ success: false, message: "Invalid role" });
        }

        // 3. Find user with valid token and check expiry
        // In PostgreSQL, we compare the current timestamp to reset_token_expiry
        const userQuery = await pool.query(
            `SELECT id FROM ${tableName} 
             WHERE id = $1 
             AND reset_token = $2 
             AND reset_token_expiry > NOW()`,
            [userId, token]
        );

        if (userQuery.rows.length === 0) {
            return res.json({ 
                success: false, 
                message: "Invalid or expired reset token. Please request a new one." 
            });
        }

        // 4. Hash the new password
        const hashedPassword = await bcrypt.hash(password, 10);

        // 5. Update password and CLEAR the token fields
        await pool.query(
            `UPDATE ${tableName} 
             SET password = $1, 
                 reset_token = NULL, 
                 reset_token_expiry = NULL 
             WHERE id = $2`,
            [hashedPassword, userId]
        );

        console.log(`[Auth] Password reset successful for ${role} ID: ${userId}`);

        return res.json({ 
            success: true, 
            message: "Password has been reset successfully. You can now log in." 
        });

    } catch (error) {
        console.error("Password Reset Error:", error);
        return res.status(500).json({ 
            success: false, 
            message: "Internal server error during password reset." 
        });
    }
});

app.post("/api/change-password", async (req, res) => {
    const { currentPassword, newPassword, role } = req.body;
    console.log('Current Password, NewPassword, Role:', currentPassword, newPassword, role);
    
    // 1. Ensure user is authenticated (Check your passport/session middleware)
    if (!req.user || !req.isAuthenticated()) {
        return res.status(401).json({ success: false, message: "Not authenticated" });
    }

    if (!currentPassword || !newPassword || !role) {
        return res.status(400).json({ success: false, message: "All fields are required" });
    }

    try {
        // 2. Determine Table (Reuse your logic)
        let tableName = "";
        if (role === "admin") tableName = "estate_admin_users";
        else if (role === "tenant") tableName = "tenant_users";
        else if (role === "temp_tenant") tableName = "temp_tenant_users";
        else if (role === "security") tableName = "security_users"; // Added for GateMan
        else return res.status(400).json({ success: false, message: "Invalid role" });

        // 3. Fetch current password hash from DB
        const userResult = await pool.query(
            `SELECT password FROM ${tableName} WHERE id = $1`, 
            [req.user.id]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        const storedHash = userResult.rows[0].password;

        // 4. Verify Current Password
        const isMatch = await bcrypt.compare(currentPassword, storedHash);
        if (!isMatch) {
            return res.json({ success: false, message: "Current password is incorrect" });
        }

        // 5. Hash New Password & Update
        const saltRounds = 10;
        const newHash = await bcrypt.hash(newPassword, saltRounds);

        await pool.query(
            `UPDATE ${tableName} SET password = $1 WHERE id = $2`,
            [newHash, req.user.id]
        );

        console.log(`[Auth] Password changed successfully for ${role} ID: ${req.user.id}`);
        
        return res.json({ 
            success: true, 
            message: "Password updated successfully" 
        });

    } catch (error) {
        console.error("Change Password Error:", error);
        return res.status(500).json({ success: false, message: "Internal server error" });
    }
});

// const password = 'dragsville';
// const hash = await bcrypt.hash(password, 10);
// console.log(hash);

io.use((socket, next) => {
    sessionMiddleware(socket.request, {}, () => {
        passport.initialize()(socket.request, {}, () => {
            passport.session()(socket.request, {}, next);
        });
    });
});

// ✅ Auth check
io.use((socket, next) => {
    if (!socket.request.user) {
        return next(new Error("Unauthorized"));
    }
    next();
});


const userStatus = new Map();

io.on("connection", (socket) => {
  const user = socket.request.user;
  const estateId = user?.estate_id; // Ensure your passport user object has estate_id

  if (user && user.id && estateId) {
    console.log(`✅ Socket connected: User ${user.id}`);
    const estateRoom = `estate_${estateId}`;
    
    // 1. Join the estate-specific neighborhood
    socket.join(estateRoom);
    socket.join(`user_${user.id}`);

    // 2. Update Map
    userStatus.set(user.id, "online");

    // 3. ONLY notify people in the same estate
    socket.to(estateRoom).emit("user_status_change", { 
      userId: user.id, 
      status: "online" 
    });

    // console.log("User status:", Array.from(userStatus.keys()));

    const currentOnlineInEstate = Array.from(userStatus.keys())

    socket.emit("initial_online_list", currentOnlineInEstate);

    socket.on("typing_start", (targetId) => {
        // console.log(`Typing: ${user.id} -> ${targetId}`);
      socket.to(`user_${targetId}`).emit("is_typing", { from: user.id, typing: true });
    });

    socket.on("typing_stop", (targetId) => {
      // console.log(`Stopped Typing: ${user.id} -> ${targetId}`);
      socket.to(`user_${targetId}`).emit("is_typing", { from: user.id, typing: false });
    })

    socket.on("disconnect", () => {
      userStatus.delete(user.id);
      // ONLY notify people in the same estate
      socket.to(estateRoom).emit("user_status_change", { 
        userId: user.id, 
        status: "offline" 
      });
    });
  }
});


// !!! IMPORTANT: Change app.listen to httpServer.listen !!!
httpServer.listen(3003, '0.0.0.0', () => 
    {
        console.log("Server running on port 3003");
        checkOverstays();
        setInterval(() => {
            checkOverstays();
        }, 10 * 60 * 1000);
    });

export { io };