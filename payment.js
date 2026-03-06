import express from 'express';
import bcrypt from 'bcrypt';
import axios from 'axios';
import Flutterwave from 'flutterwave-node-v3';
import pool from './db.js';
import crypto from 'crypto';


const router = express.Router();
const flw = new Flutterwave(process.env.FW_PUBLIC, process.env.FW_SECRET);

router.post('/', async (req, res) => {
    console.log('reg details:', req.body)
    try {
        const { name, email, password, city, town } = req.body;

        if (!name || !email || !password) {
        return res.status(400).json({ error: "Name, email, and password are required" });
        }

        const emailCheck = await pool.query(
            `SELECT email FROM estate_admin_users WHERE email = $1`,
            [email]
        );

        if (emailCheck.rows.length > 0) {
            return res.status(400).json({ error: "This email is already an active administrator." });
        }

        const estateCheck = await pool.query(
            `SELECT id FROM estates 
             WHERE LOWER(name) = LOWER($1) AND LOWER(city) = LOWER($2) AND LOWER(town) = LOWER($3)`,
            [name, city, town]
        );

        if (estateCheck.rows.length > 0) {
            return res.status(400).json({ error: "An estate with this name already exists in this location." });
        }

        const amount = 1;
        const tx_ref = `${email}_${Date.now()}`; 

        // Initiate payment
        const paymentData = {
        tx_ref,
        amount,
        currency: "USD",
        redirect_url: "https://0cbb-102-88-54-47.ngrok-free.app/api/payment/callback",
        payment_options: "card",
        customer: { email, name }
        };

        const response = await axios.post(
        'https://api.flutterwave.com/v3/payments',
        paymentData,
        {
            headers: {
            'Authorization': `Bearer ${process.env.FW_SECRET}`,
            'Content-Type': 'application/json'
            }
        }
        );

        // Hash password before storing in temp_payments
        const hashedPassword = await bcrypt.hash(password, 10);

        // Save temp user with tx_ref
        await pool.query(
        `INSERT INTO temp_payment_info (tx_ref, name, email, password, city, town) 
        VALUES ($1, $2, $3, $4, $5, $6)`,
        [tx_ref, name, email, hashedPassword, city || null, town || null]
    );

        // Return payment link to frontend
        res.json({ paymentLink: response.data.data.link });

    } catch (error) {
        console.error("Payment Error:", error.response?.data || error.message);
        res.status(500).json({ error: 'Payment failed' });
    }
});


router.post('/flutterwave-webhook', async (req, res) => {
  console.log('webhook hit!')
  const client = await pool.connect();
  try {
    const payload = req.body;
    const tx_ref = payload.txRef;

    
    // Verify Flutterwave signature
    const secretHash = process.env.FLW_SECRET_HASH;
    const flutterwaveSignature = req.headers['verif-hash'];
    // console.log('Verif- hash:', flutterwaveSignature)
    if (!flutterwaveSignature || flutterwaveSignature !== secretHash) {
      console.log('Invalid signature')
      return res.status(403).json({ error: 'Invalid signature' });
    }

    if (payload.status !== 'successful') {
      return res.sendStatus(200);
    }

    // Look up temp user through the client
    const tempUserResult = await client.query(
      'SELECT * FROM temp_payment_info WHERE tx_ref = $1',
      [tx_ref]
    );

    if (tempUserResult.rows.length === 0) {
      console.error('Temp payment not found for tx_ref:', tx_ref);
      return res.sendStatus(404);
    }

    const tempUser = tempUserResult.rows[0];

    // Begin transaction
    await client.query('BEGIN');

    // Create Estate
    const estateCode = crypto.randomBytes(3).toString('hex').toUpperCase();
    const estateResult = await client.query(
      'INSERT INTO estates (name, estate_code) VALUES ($1, $2) RETURNING id',
      [`${tempUser.name}'s Estate`, estateCode]
    );
    const estateId = estateResult.rows[0].id;

    // Subscription expiry
    const subscriptionExpiry = new Date();
    subscriptionExpiry.setFullYear(subscriptionExpiry.getFullYear() + 1);

    // Insert into estate_admin_users with city/town
    await client.query(
      `INSERT INTO estate_admin_users 
       (estate_id, name, email, password, city, town, subscription_expiry) 
       VALUES ($1, $2, $3, $4, $5, $6, $7)`,
      [
        estateId,
        tempUser.name,
        tempUser.email,
        tempUser.password,
        tempUser.city || null,
        tempUser.town || null,
        subscriptionExpiry
      ]
    );

    // Delete temp record
    await client.query(
      'DELETE FROM temp_payment_info WHERE tx_ref = $1',
      [tx_ref]
    );

    // Commit
    await client.query('COMMIT');

    console.log(`✅ Estate and admin user created for ${tempUser.email}`);
    res.sendStatus(200);

  } catch (error) {
    await client.query('ROLLBACK');
    console.error('Webhook transaction error:', error); // log full error
    res.status(500).json({ error: 'Internal server error' });
  } finally {
    client.release();
  }
});


router.get('/callback', async (req, res) => {
    const transactionId = req.query.transaction_id;
    console.log(transactionId);

    try {
        const response = await flw.Transaction.verify({ id: transactionId });
        // console.log(response);

        if (
            response.data.status === "successful" &&
            response.data.currency === "USD"
        ) {
            res.redirect(`http://localhost:3005/payment-success`);
        } else {
            res.redirect(`http://localhost:3005/payment-failure`);
        }
    } catch (err) {
        console.error(err);
        res.send("An error occurred during verification.");
    }
});

export default router;
