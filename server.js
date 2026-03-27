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


dotenv.config();


const allowedOrigins = [
  "https://estatemate.snametech.app", 
  "http://localhost:3005", 
  "http://localhost:8081" // Standard Expo port
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

app.get("/api/session-check", (req, res) => {
    if (req.isAuthenticated && req.isAuthenticated()) {
        res.json({ success: true});
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

// const password = 'dragsville123';
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
httpServer.listen(3003, '0.0.0.0', () => console.log("Server running on port 3003"));
