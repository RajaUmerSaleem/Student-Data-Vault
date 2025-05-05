import nodemailer from 'nodemailer';
import dotenv from 'dotenv';
dotenv.config(); 
const createTransporter = () => {
  try {
    
    return nodemailer.createTransport({
      host: process.env.EMAIL_HOST, 
      port: process.env.EMAIL_PORT, 
      secure: false, 
      auth: {
        user: process.env.EMAIL_USER, 
        pass: process.env.EMAIL_PASS, 
      },
    });
  } catch (error) {
    console.error('Failed to create email transporter:', error);
    return null;
  }
};

export async function sendEmail(to, subject, text, html) {
  try {
    const transporter = createTransporter();

    if (!transporter) {
      console.error('Email transporter not configured');
      return false;
    }

    const info = await transporter.sendMail({
      from: process.env.EMAIL_FROM,
      to,
      subject,
      text,
      html,
    });

    console.log('Email sent successfully:', info.messageId);
    return true;
  } catch (error) {
    console.error(`Failed to send email to ${to}:`, error);
    return false;
  }
}