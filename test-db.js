// test-db.js
import pg from "pg";
import dotenv from "dotenv";
dotenv.config();

const pool = new pg.Pool({
    connectionString: process.env.DATABASE_URL,
});

async function testConnection() {
    try {
        const res = await pool.query("SELECT NOW()");
        console.log("✅ Connected! Server time:", res.rows[0]);
    } catch (err) {
        console.error("❌ Connection failed:", err.message);
    } finally {
        await pool.end();
    }
}

testConnection();
