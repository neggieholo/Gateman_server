// routes/invoices.ts
import express from 'express';
import pool from './db.js';

const router = express.Router();

// Function to generate invoices for a single bill
async function generateTenantInvoicesFromEstateInvoice(estateInvoiceId) {
  // 1. Fetch estate invoice
  const estateInvoiceRes = await pool.query(
    `SELECT ei.*, bi.amount AS total_amount
     FROM estate_invoices ei
     JOIN billable_items bi ON bi.id = ei.bill_id
     WHERE ei.id = $1`,
    [estateInvoiceId]
  );
  if (estateInvoiceRes.rowCount === 0)
    throw new Error('Estate invoice not found');

  const estateInvoice = estateInvoiceRes.rows[0];

  // 2. Fetch tenants
  const tenantsRes = await pool.query(
    'SELECT id FROM tenant_users WHERE estate_id = $1',
    [estateInvoice.estate_id]
  );
  const tenants = tenantsRes.rows;
  if (!tenants.length) throw new Error('No tenants found');

  // 3. Split amount (MVP: equal share)
  const amountPerTenant = Number(estateInvoice.total_amount) / tenants.length;
  const invoicesCreated = [];

  for (const tenant of tenants) {
    const invoiceRes = await pool.query(
      `INSERT INTO invoices 
        (tenant_id, estate_id, bill_id, invoice_month, total_amount)
       VALUES ($1,$2,$3,$4,$5)
       RETURNING id`,
      [
        tenant.id,
        estateInvoice.estate_id,
        estateInvoice.bill_id,
        estateInvoice.period_start || new Date(),
        amountPerTenant
      ]
    );

    const invoiceId = invoiceRes.rows[0].id;

    // Optional: create invoice item
    await pool.query(
      `INSERT INTO invoice_items (invoice_id, item_name, amount, quantity)
       VALUES ($1,$2,$3,$4)`,
      [invoiceId, estateInvoice.supplier_name, amountPerTenant, 1]
    );

    invoicesCreated.push(invoiceId);
  }

  return invoicesCreated;
}


// Manual invoice generation endpoint
router.post('/estate_invoice', async (req, res) => {
  try {
    const { billId, calculationMethod, periodStart, periodEnd, supplier_name, notes, invoice_type } = req.body;
    const estateId = req.user.estate_id;

    // Fetch billable item
    const billRes = await pool.query(
      `SELECT id, name, amount FROM billable_items WHERE id = $1 AND estate_id = $2`,
      [billId, estateId]
    );
    if (billRes.rowCount === 0)
      return res.status(404).json({ success: false, message: 'Bill not found' });

    const bill = billRes.rows[0];

    // Create estate invoice
    const estateInvoiceRes = await pool.query(
    `INSERT INTO estate_invoices 
      (estate_id, bill_id, supplier_name, calculation_method, notes, period_start, period_end, invoice_type)
    VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
    RETURNING id`,
    [estateId, bill.id, supplier_name, calculationMethod || 'EQUAL', notes, periodStart, periodEnd, invoice_type]
);


    const estateInvoiceId = estateInvoiceRes.rows[0].id;
    generateTenantInvoicesFromEstateInvoice(estateInvoiceId)

    return res.json({ success: true, estateInvoiceId });
  } catch (err) {
    console.error('Create estate invoice error:', err);
    return res.status(500).json({ success: false, message: err.message });
  }
});


router.post('/special', async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    const estateId = req.user.estateId;
    const createdBy = req.user.id;
    const { tenantIds, billId,supplier_name, notes ,calculationMethod, periodStart, periodEnd } = req.body;

    // Validate input
    if (!billId) return res.status(400).json({ success: false, message: 'billId is required' });
    if (!tenantIds || !Array.isArray(tenantIds) || tenantIds.length === 0) {
      return res.status(400).json({ success: false, message: 'tenantIds is required' });
    }

    // Fetch billable item
    const billRes = await pool.query(
      `SELECT id, name, amount FROM billable_items WHERE id = $1 AND estate_id = $2`,
      [billId, estateId]
    );
    if (billRes.rowCount === 0) return res.status(404).json({ success: false, message: 'Billable item not found' });

    const bill = billRes.rows[0];

    // Validate tenants
    const tenantCheck = await pool.query(
      `SELECT id FROM tenant_users WHERE estate_id = $1 AND id = ANY($2)`,
      [estateId, tenantIds]
    );
    if (tenantCheck.rowCount !== tenantIds.length) {
      return res.status(400).json({
        success: false,
        message: "One or more tenant IDs are invalid or do not belong to this estate",
        validTenants: tenantCheck.rows.map(t => t.id),
        invalidTenants: tenantIds.filter(id => !tenantCheck.rows.find(t => t.id === id))
      });
    }

    // 1. Create estate invoice
    const estateInvoiceRes = await pool.query(
      `INSERT INTO estate_invoices 
        (estate_id, bill_id, supplier_name, calculation_method,notes, period_start, period_end, created_by)
       VALUES ($1,$2,$3,$4,$5,$6,$7,$8)
       RETURNING id, bill_id`,
      [estateId, bill.id, supplier_name, 'EQUAL', periodStart || null,notes, periodEnd || null, createdBy]
    );
    const estateInvoiceId = estateInvoiceRes.rows[0].id;

    // 2. Split amount equally among selected tenants (MVP)
    const amountPerTenant = Number(bill.amount) / tenantIds.length;
    const invoicesCreated = [];

    // 3. Generate tenant invoices
    for (const tenantId of tenantIds) {
      const invoiceRes = await pool.query(
        `INSERT INTO invoices 
          (tenant_id, estate_id, bill_id, estate_invoice_id, invoice_month, total_amount)
         VALUES ($1,$2,$3,$4,$5,$6)
         RETURNING id`,
        [
          tenantId,
          estateId,
          bill.id,
          estateInvoiceId,
          periodStart || new Date(), // Use periodStart or today
          amountPerTenant
        ]
      );
      const invoiceId = invoiceRes.rows[0].id;

      // Create invoice item
      await pool.query(
        `INSERT INTO invoice_items (invoice_id, item_name, amount, quantity)
         VALUES ($1, $2, $3, 1)`,
        [invoiceId, bill.name, amountPerTenant]
      );

      invoicesCreated.push({ tenantId, invoiceId, amount: amountPerTenant });
    }

    return res.json({
      success: true,
      message: "Special tenant invoices created successfully",
      estateInvoiceId,
      invoicesCreated
    });

  } catch (err) {
    console.error("Special invoice error:", err);
    return res.status(500).json({ success: false, message: err.message });
  }
});


router.get('/singular/:id', async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    const estateId = req.user.estateId;
    const { id } = req.params;

    // Fetch invoice
    const invoiceRes = await pool.query(
      `
      SELECT 
        i.*, 
        tu.name AS tenant_name,
        tu.unit,
        bi.name AS bill_name
      FROM invoices i
      JOIN tenant_users tu ON tu.id = i.tenant_id
      JOIN billable_items bi ON bi.id = i.bill_id
      WHERE i.id = $1 AND i.estate_id = $2
      `,
      [id, estateId]
    );

    if (invoiceRes.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Invoice not found' });
    }

    // Fetch invoice items
    const itemRes = await pool.query(
      `SELECT * FROM invoice_items WHERE invoice_id = $1 ORDER BY created_at ASC`,
      [id]
    );

    return res.json({
      success: true,
      invoice: invoiceRes.rows[0],
      items: itemRes.rows,
    });

  } catch (err) {
    console.error('Fetch invoice error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});


router.get('/', async (req, res) => {
  console.log('generate invoiceapi hit')
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    const estateId = req.user.estate_id;

    // 1. Fetch invoices with tenant info
    const invoicesRes = await pool.query(
      `
      SELECT 
        i.*,
        tu.id AS tenant_id,
        tu.name AS tenant_name,
        tu.block AS tenant_block,
        tu.unit AS tenant_unit
      FROM invoices i
      JOIN tenant_users tu ON tu.id = i.tenant_id
      WHERE i.estate_id = $1
      ORDER BY i.created_at DESC
      `,
      [estateId]
    );

    const invoices = invoicesRes.rows;

    // 2. Fetch all invoice items for these invoices
    const invoiceIds = invoices.map(inv => inv.id);
    let items = [];
    if (invoiceIds.length > 0) {
      const itemsRes = await pool.query(
        `
        SELECT *
        FROM invoice_items
        WHERE invoice_id = ANY($1::uuid[])
        ORDER BY created_at ASC
        `,
        [invoiceIds]
      );
      items = itemsRes.rows;
    }

    // 3. Combine items with their invoices
    const invoicesWithItems = invoices.map(inv => ({
      ...inv,
      items: items.filter(item => item.invoice_id === inv.id),
      tenant: {
        id: inv.tenant_id,
        name: inv.tenant_name,
        block: inv.tenant_block,
        unit: inv.tenant_unit,
      },
    }));

    return res.json({ success: true, invoices: invoicesWithItems });

  } catch (err) {
    console.error('Fetch invoices error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});

/**
 * GET /general-invoices
 * Fetch all general invoices for the logged-in estate
 */
router.get('/estate_invoices', async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    const estateId = req.user.estate_id;

    // Fetch estate invoices
    const estateInvoicesRes = await pool.query(
    `
    SELECT 
      ei.id,
      ei.bill_id,
      ei.supplier_name,
      ei.calculation_method,
      ei.period_start,
      ei.period_end,
      ei.attachment_image_path,
      ei.attachment_pdf_path,
      ei.notes,
      ei.created_at,
      ei.updated_at,
      ei.created_by,
      bi.name AS bill_name,
      bi.amount AS total_amount,
      u.name AS created_by_name
    FROM estate_invoices ei
    LEFT JOIN billable_items bi ON bi.id = ei.bill_id
    LEFT JOIN estate_admin_users u ON u.id = ei.created_by
    WHERE ei.estate_id = $1
    ORDER BY ei.created_at DESC
    `,
    [estateId]
);


    return res.json({
      success: true,
      estateInvoices: estateInvoicesRes.rows
    });

  } catch (err) {
    console.error('Fetch estate invoices error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});




router.delete('/:id', async (req, res) => {
  try {
    if (!req.user) {
      return res.status(401).json({ success: false, message: 'Not authorized' });
    }

    const estateId = req.user.estateId;
    const { id } = req.params;

    // Confirm invoice exists and not paid
    const check = await pool.query(
      `SELECT status FROM invoices WHERE id = $1 AND estate_id = $2`,
      [id, estateId]
    );

    if (check.rowCount === 0) {
      return res.status(404).json({ success: false, message: 'Invoice not found' });
    }

    if (check.rows[0].status === 'paid') {
      return res
        .status(400)
        .json({ success: false, message: 'Cannot delete a fully paid invoice' });
    }

    // Delete invoice
    await pool.query(
      `DELETE FROM invoices WHERE id = $1 AND estate_id = $2`,
      [id, estateId]
    );

    return res.json({ success: true, message: 'Invoice deleted' });

  } catch (err) {
    console.error('Delete invoice error:', err);
    return res.status(500).json({ success: false, message: 'Server error' });
  }
});



export default router;
