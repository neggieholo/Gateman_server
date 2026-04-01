import nodemailer from 'nodemailer';

// Configure the ZeptoMail Transporter
const transporter = nodemailer.createTransport({
    host: "smtp.zeptomail.com",
    port: 465,
    auth: {
    user: "emailapikey",
    pass: "wSsVR60i+xHwDqcrnGGlcrxtmwhTUVn+HU8s2AHw63b5HfvC8sc+kkXHDFejG6IYGWRqQDETrb8tzEtV2mEL3dQuzV0GCyiF9mqRe1U4J3x17qnvhDzPV29emhCOL44BwgRpnmdhG8kk+g=="
    }
});


const APP_NAME = "GateMan";
const FROM_EMAIL = '"GateMan" <noreply@gatemanhq.com>';

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