import nodemailer from 'nodemailer';

// Configure the ZeptoMail Transporter
// const transporter = nodemailer.createTransport({
//     host: "smtp.zeptomail.com",
//     port: 465,
//     auth: {
//     user: "emailapikey",
//     pass: "wSsVR60i+xHwDqcrnGGlcrxtmwhTUVn+HU8s2AHw63b5HfvC8sc+kkXHDFejG6IYGWRqQDETrb8tzEtV2mEL3dQuzV0GCyiF9mqRe1U4J3x17qnvhDzPV29emhCOL44BwgRpnmdhG8kk+g=="
//     }
// });

const transporter = nodemailer.createTransport({
  name: "employeetracker.app",
  host: "smtp.hostinger.com",
  port: 465,
  secure: true,
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
  debug: true, // Enable debugging
  logger: true, // Log SMTP responses
});

const APP_NAME = "GateMan";
const FROM_EMAIL = '"GateMan" <support@employeetracker.app>';

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
 * Send Event Guest Access Code (RSVP Success)
 */
export const sendEventGuestCode = async (email, guestName, eventName, guestCode) => {
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