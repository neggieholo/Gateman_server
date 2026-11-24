import pg from "pg";
import dotenv from "dotenv";
dotenv.config();

pg.types.setTypeParser(1184, (val) => val);

const pool = new pg.Pool({
  connectionString: process.env.DATABASE_URL,
  // ssl: {
  //   rejectUnauthorized: false, // This tells pg to accept the AWS self-signed cert
  // },
});

export default pool;
