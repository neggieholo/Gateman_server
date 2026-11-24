import nodemailer from "nodemailer";

const transporter = nodemailer.createTransport({
  name: "gatemanhq.com",
  host: "smtp.hostinger.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER || "ceo@gatemanhq.com",
    pass: process.env.EMAIL_PASS || "katia_obas@gatemanHQ2026",
  },
  debug: true, // Enable debugging
  logger: true, // Log SMTP responses
});

const APP_NAME = "GateMan";
const FROM_EMAIL = '"GateMan" <ceo@gatemanhq.com>';

/**
 * Send Registration OTP
 */
export const sendRegistrationOTP = async (email, otp) => {
  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Verify your ${APP_NAME} email account`,
      html: `
        <div style="font-family: sans-serif; max-width: 400px; margin: auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 12px;">
          <h2 style="color: #4f46e5; text-align: center;">Verify Your Account</h2>
          <p style="font-size: 14px; color: #4b5563; text-align: center;">Enter this code in the ${APP_NAME} app to activate your resident profile.</p>
          <div style="background: #f9fafb; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
            <h1 style="margin: 0; letter-spacing: 10px; color: #111827; font-size: 32px; font-weight: bold;">${otp}</h1>
          </div>
          <p style="font-size: 12px; color: #9ca3af; text-align: center;">This code expires in 10 minutes. Please do not share this code with anyone.</p>
        </div>
      `,
    });
    return true;
  } catch (error) {
    console.error("OTP Email Error:", error);
    return false;
  }
};

/**
 * Send Password Reset Code
 */
export const sendPasswordResetCode = async (email, resetLink) => {
  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Reset your ${APP_NAME} password`,
      html: `
            <p>You requested a password reset. Click the button below to reset your password:</p>
            <p><a href="${resetLink}" style="background-color:#007bff;color:white;padding:10px 20px;text-decoration:none;border-radius:5px;">Reset Password</a></p>
            <p>If you did not request this, please ignore this email.</p>
        `,
    });
    return true;
  } catch (error) {
    console.error("Reset Email Error:", error);
    return false;
  }
};

/**
 * Send Temporary Password
 */
export const sendTemporaryPasswordEmail = async (email, tempPassword) => {
  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Your Temporary Password for ${APP_NAME}`,
      html: `
        <div style="font-family: sans-serif; max-width: 400px; margin: auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 12px;">
          <h2 style="color: #4f46e5; text-align: center;">Temporary Password</h2>
          <p style="font-size: 14px; color: #4b5563; text-align: center;">Use the temporary password below to log into your ${APP_NAME} account.</p>
          <div style="background: #f9fafb; padding: 20px; border-radius: 8px; text-align: center; margin: 20px 0;">
            <h1 style="margin: 0; letter-spacing: 8px; color: #111827; font-size: 32px; font-weight: bold;">${tempPassword}</h1>
          </div>
          <p style="font-size: 13px; color: #ef4444; text-align: center; font-weight: bold;">You will be required to change your password immediately upon logging in.</p>
        </div>
      `,
    });
    return true;
  } catch (error) {
    console.error("Temporary Password Email Error:", error);
    return false;
  }
};

/**
 * Send Event Guest Access Code (RSVP Success)
 */
export const sendEventGuestCode = async (
  email,
  guestName,
  eventName,
  guestCode,
) => {
  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Your Visitor Pass for ${eventName}`,
      html: `
        <div style="font-family: sans-serif; max-width: 450px; margin: auto; padding: 20px; border: 1px solid #e5e7eb; border-radius: 24px; background-color: #ffffff;">
          <div style="text-align: center; margin-bottom: 20px;">
            <span style="background: #e0e7ff; color: #4338ca; padding: 5px 15px; border-radius: 20px; font-size: 12px; font-weight: bold; text-transform: uppercase;">Event Access Pass</span>
          </div>
          
          <h2 style="color: #111827; text-align: center; margin-top: 0;">Hi ${guestName},</h2>
          <p style="font-size: 15px; color: #4b5563; text-align: center; line-height: 1.5;">
            Your registration for <strong>${eventName}</strong> is confirmed. Please present the code below to the security personnel at the gate.
          </p>

          <div style="background: #f3f4f6; border: 2px dashed #d1d5db; padding: 25px; border-radius: 16px; text-align: center; margin: 25px 0;">
            <p style="margin: 0 0 10px 0; font-size: 11px; color: #6b7280; font-weight: bold; uppercase; letter-spacing: 1px;">GUEST ENTRY CODE</p>
            <h1 style="margin: 0; color: #4f46e5; font-size: 36px; font-weight: 900; letter-spacing: 2px;">${guestCode}</h1>
          </div>

          <div style="background: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px; margin-bottom: 20px;">
            <p style="margin: 0; font-size: 13px; color: #92400e;">
              <strong>Note:</strong> This code is valid for a single entry. Do not share this code with anyone else.
            </p>
          </div>

          <p style="font-size: 12px; color: #9ca3af; text-align: center; border-top: 1px solid #f3f4f6; padding-top: 20px;">
            Powered by <strong>${APP_NAME}</strong> - Smart Estate Security
          </p>
        </div>
      `,
    });
    return true;
  } catch (error) {
    console.error("Event Email Error:", error);
    return false;
  }
};

/**
 * Send Admin Welcoming Credentials
 */
export const sendAdminWelcomeEmail = async (
  email,
  fullName,
  rawPassword,
  mustChangePassword,
  hasPhone = false,
) => {
  try {
    const credentialLabel = hasPhone
      ? "Temporary Password (Part 1 - Email)"
      : "Temporary Password";

    const passwordNotice = hasPhone
      ? `This is <strong>Part 1</strong> of your temporary password. The second part has been dispatched to your registered mobile phone via SMS. Combine both parts (<strong>Email Part + SMS Part</strong>) in that exact order to log into your workspace dashboard.`
      : `Use these credentials to log into your workspace dashboard.`;

    const passwordRotationNotice = mustChangePassword
      ? `
        <div style="background: #fffbeb; border-left: 4px solid #f59e0b; padding: 15px; margin: 20px 0; border-radius: 0 8px 8px 0;">
          <p style="margin: 0; font-size: 13px; color: #92400e; line-height: 1.5;">
            <strong>⚠️ Mandatory Action Required:</strong> You are required to update this temporary password immediately during your first login sequence. Failure to do so will restrict your workspace entry access.
          </p>
        </div>
      `
      : "";

    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Your ${APP_NAME} Administrative Workspace is Ready`,
      html: `
        <div style="font-family: sans-serif; max-width: 450px; margin: auto; padding: 25px; border: 1px solid #e5e7eb; border-radius: 24px; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
          <div style="text-align: center; margin-bottom: 20px;">
            <span style="background: #e0e7ff; color: #4338ca; padding: 6px 16px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">Staff Account Deployed</span>
          </div>
          
          <h2 style="color: #111827; margin-top: 0; font-size: 20px;">Welcome to the Team, ${fullName}!</h2>
          <p style="font-size: 14px; color: #4b5563; line-height: 1.6; margin-bottom: 20px;">
            An administrative profile has been securely provisioned for you on the <strong>${APP_NAME}</strong> platform. ${passwordNotice}
          </p>

          <div style="background: #f9fafb; border: 1px solid #e5e7eb; padding: 20px; border-radius: 16px; margin-bottom: 20px;">
            <p style="margin: 0 0 8px 0; font-size: 13px; color: #374151;"><strong>Login Identity:</strong> <span style="color: #4f46e5; font-family: monospace;">${email}</span></p>
            <p style="margin: 0; font-size: 13px; color: #374151;"><strong>${credentialLabel}:</strong> <span style="color: #111827; font-family: monospace; font-weight: bold; background: #f3f4f6; padding: 2px 6px; border-radius: 4px;">${rawPassword}</span></p>
          </div>

          <div style="background: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; border-radius: 0 8px 8px 0;">
            <p style="margin: 0; font-size: 13px; color: #1e40af; line-height: 1.5;">
              <strong>ℹ️ Email Verification Sequence:</strong> After entering these credentials at login, an authentication token will be delivered to this email box to verify ownership before your workspace opens.
            </p>
          </div>

          ${passwordRotationNotice}

          <p style="font-size: 12px; color: #9ca3af; text-align: center; border-top: 1px solid #f3f4f6; padding-top: 20px; margin-top: 25px;">
            Powered by <strong>${APP_NAME}</strong> - HQ Security Management Suite
          </p>
        </div>
      `,
    });
    return true;
  } catch (error) {
    console.error("Welcome Email Dispatch Operational Failure:", error);
    return false;
  }
};

export const sendTenantWelcomeEmail = async (
  email,
  fullName,
  rawPassword,
  isSubAccount = false,
) => {
  try {
    const credentialLabel = isSubAccount
      ? "Temporary Password (Part 1 - Email)"
      : "Temporary Password";

    const securityNotice = isSubAccount
      ? `This is <strong>Part 1</strong> of your temporary password. The second part has been dispatched to your mobile phone via SMS. Combine both parts (<strong>Email Part + SMS Part</strong>) in that exact order to log in.`
      : `Download the ${APP_NAME} mobile application, log in using these credentials, and you will be prompted to set up your permanent secure password right away.`;

    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Your ${APP_NAME} Resident Profile Is Ready`,
      html: `
        <div style="font-family: sans-serif; max-width: 450px; margin: auto; padding: 25px; border: 1px solid #e5e7eb; border-radius: 24px; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
          <div style="text-align: center; margin-bottom: 20px;">
            <span style="background: #ecfdf5; color: #065f46; padding: 6px 16px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">Resident Account Ready</span>
          </div>
          
          <h2 style="color: #111827; margin-top: 0; font-size: 20px;">Welcome, ${fullName}!</h2>
          <p style="font-size: 14px; color: #4b5563; line-height: 1.6; margin-bottom: 20px;">
            An official resident profile has been provisioned for you by your estate's management on the <strong>${APP_NAME}</strong> platform. 
          </p>

          <div style="background: #f9fafb; border: 1px solid #e5e7eb; padding: 20px; border-radius: 16px; margin-bottom: 20px;">
            <p style="margin: 0 0 8px 0; font-size: 13px; color: #374151;"><strong>Username/Email:</strong> <span style="color: #4f46e5; font-family: monospace;">${email}</span></p>
            <p style="margin: 0; font-size: 13px; color: #374151;"><strong>${credentialLabel}:</strong> <span style="color: #111827; font-family: monospace; font-weight: bold; background: #f3f4f6; padding: 2px 6px; border-radius: 4px;">${rawPassword}</span></p>
          </div>

          <div style="background: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; border-radius: 0 8px 8px 0;">
            <p style="margin: 0; font-size: 13px; color: #1e40af; line-height: 1.5;">
              <strong>🔐 Getting Started:</strong> ${securityNotice}
            </p>
          </div>

          <p style="font-size: 12px; color: #9ca3af; text-align: center; border-top: 1px solid #f3f4f6; padding-top: 20px; margin-top: 25px;">
            Powered by <strong>${APP_NAME}</strong> - Smart Estate Security
          </p>
        </div>
      `,
    });
    return true;
  } catch (error) {
    console.error("Tenant Welcome Email Dispatch Failure:", error);
    return false;
  }
};

export const sendTenantApprovalEmail = async (email, fullName, estateName) => {
  try {
    await transporter.sendMail({
      from: FROM_EMAIL,
      to: email,
      subject: `Residency Approved - ${estateName || APP_NAME}`,
      html: `
        <div style="font-family: sans-serif; max-width: 450px; margin: auto; padding: 25px; border: 1px solid #e5e7eb; border-radius: 24px; background-color: #ffffff; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.05);">
          <div style="text-align: center; margin-bottom: 20px;">
            <span style="background: #ecfdf5; color: #065f46; padding: 6px 16px; border-radius: 20px; font-size: 11px; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px;">Residency Approved 🎉</span>
          </div>
          
          <h2 style="color: #111827; margin-top: 0; font-size: 20px;">Welcome, ${fullName}!</h2>
          <p style="font-size: 14px; color: #4b5563; line-height: 1.6; margin-bottom: 20px;">
            Your residency application for <strong>${estateName || "your estate"}</strong> has been officially approved by management.
          </p>

          <div style="background: #eff6ff; border-left: 4px solid #3b82f6; padding: 15px; margin: 20px 0; border-radius: 0 8px 8px 0;">
            <p style="margin: 0; font-size: 13px; color: #1e40af; line-height: 1.5;">
              <strong>🚀 Next Steps:</strong> Log in using your existing account credentials to access your updated resident dashboard.
            </p>
          </div>

          <p style="font-size: 12px; color: #9ca3af; text-align: center; border-top: 1px solid #f3f4f6; padding-top: 20px; margin-top: 25px;">
            Powered by <strong>${APP_NAME}</strong> — Smart Estate Security
          </p>
        </div>
      `,
    });
    return true;
  } catch (error) {
    console.error("Tenant Approval Email Dispatch Failure:", error);
    return false;
  }
};
