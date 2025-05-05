import { Router } from 'express';
import crypto from 'crypto';
import jwt from 'jsonwebtoken';
import { createHash } from 'crypto';
import User from '../models/user.js';
import Log from '../models/log.js';
import { sendEmail } from '../utils/email.js';
import { verifyToken, restrictTo } from '../middleware/auth.js';

const router = Router();

// AES encryption/decryption utilities
const AES_KEY = Buffer.from('0123456789abcdef0123456789abcdef');
const IV_LENGTH = 16;

function encryptData(data) {
  const iv = crypto.randomBytes(IV_LENGTH);
  const cipher = crypto.createCipheriv('aes-256-cbc', AES_KEY, iv);
  let encrypted = cipher.update(data, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return { encryptedData: encrypted, iv: iv.toString('hex') };
}

function decryptData(encryptedData, iv) {
  const decipher = crypto.createDecipheriv('aes-256-cbc', AES_KEY, Buffer.from(iv, 'hex'));
  let decrypted = decipher.update(encryptedData, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// POST /api/auth/qr - Login with QR code
router.post('/qr', async (req, res) => {
  const { qr } = req.body;

  try {
    // Validate QR token
    if (!qr) {
      return res.status(400).json({ error: 'QR token is required' });
    }

    // Check if JWT_SECRET is configured
    if (!process.env.JWT_SECRET) {
      console.error('JWT_SECRET is not configured in environment variables');
      return res.status(500).json({ error: 'Server configuration error' });
    }

    // Find user by QR token
    const user = await User.findOne({ qrToken: qr });
    if (!user) {
      // Log failed attempt
      await Log.create({
        userId: 'unknown',
        role: 'unknown',
        action: 'qr_login_failed',
        hash: createHash('sha256').update('qr_login_failed').digest('hex'),
      });

      console.warn('Invalid QR token detected');
      return res.status(401).json({ error: 'Invalid QR token' });
    }

    // Update last login time
    user.lastLogin = Date.now();
    await user.save();

    // Generate JWT
    const token = jwt.sign(
      { id: user.userId, role: user.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );

    // Log successful login
    await Log.create({
      userId: user.userId,
      role: user.role,
      action: 'qr_login',
      hash: createHash('sha256').update('qr_login').digest('hex'),
    });

    // Decrypt email for notification
    let userEmail;
    try {
      if (user.email && user.email.encryptedData && user.email.iv) {
        userEmail = decryptData(user.email.encryptedData, user.email.iv);
      } else {
        console.error('Email data is corrupted or missing');
        userEmail = 'no-email@example.com';
      }
    } catch (decryptError) {
      console.error('Failed to decrypt email:', decryptError);
      userEmail = 'no-email@example.com';
    }

    // Send email notification for login
    const emailContent = `
      <h2>Login Notification</h2>
      <p>Hi ${user.fullName},</p>
      <p>Your account was successfully accessed on ${new Date().toLocaleString()} by Qr Smart Card.</p>
      <p>If this wasn't you, please contact support immediately.</p>
    `;

    try {
      await sendEmail(
        userEmail,
        'Account Login Notification',
        `Hi ${user.fullName},\n\nYour account was successfully accessed at ${new Date().toLocaleString()} by Card Scan.`,
        emailContent
      );
    } catch (emailError) {
      console.error('Failed to send login notification:', emailError);
      // Continue even if email fails
    }

    // Respond with token and role
    res.json({ token, role: user.role, userId: user.userId });
  } catch (err) {
    console.error('Error during QR login:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/login - Email/password login
router.post('/login', async (req, res) => {
  const { email, password } = req.body;
  
  try {
    if (!email || !password) {
      return res.status(400).json({ error: 'Email and password are required' });
    }

    // Find all users and check emails by decrypting them
    const users = await User.find({});
    let matchedUser = null;
    
    // Iterate through users to find matching email
    for (const user of users) {
      if (user.email && user.email.encryptedData && user.email.iv) {
        try {
          const decryptedEmail = decryptData(user.email.encryptedData, user.email.iv);
          if (decryptedEmail.toLowerCase() === email.toLowerCase()) {
            matchedUser = user;
            break;
          }
        } catch (decryptError) {
          console.error('Failed to decrypt email during login attempt:', decryptError);
        }
      }
    }
    
    // If no user found or password doesn't exist
    if (!matchedUser || !matchedUser.password) {
      await Log.create({
        userId: 'unknown',
        role: 'unknown',
        action: 'email_login_failed',
        hash: createHash('sha256').update('email_login_failed').digest('hex'),
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Verify password
    const isValid = await matchedUser.comparePassword(password);
    if (!isValid) {
      await Log.create({
        userId: matchedUser.userId,
        role: matchedUser.role,
        action: 'password_verification_failed',
        hash: createHash('sha256').update('password_verification_failed').digest('hex'),
      });
      return res.status(401).json({ error: 'Invalid credentials' });
    }
    
    // Update last login time
    matchedUser.lastLogin = Date.now();
    await matchedUser.save();
    
    // Generate JWT
    const token = jwt.sign(
      { id: matchedUser.userId, role: matchedUser.role },
      process.env.JWT_SECRET,
      { expiresIn: '1h' }
    );
    
    // Log successful login
    await Log.create({
      userId: matchedUser.userId,
      role: matchedUser.role,
      action: 'email_login',
      hash: createHash('sha256').update('email_login').digest('hex'),
    });
    
    // Send login notification
    try {
      const userEmail = decryptData(matchedUser.email.encryptedData, matchedUser.email.iv);
      
      const emailContent = `
        <h2>Login Notification</h2>
        <p>Hi ${matchedUser.fullName},</p>
        <p>Your account was successfully accessed on ${new Date().toLocaleString()} using email/password login.</p>
        <p>If this wasn't you, please change your password immediately.</p>
      `;
      
      await sendEmail(
        userEmail,
        'Account Login Notification',
        `Hi ${matchedUser.fullName},\n\nYour account was successfully accessed using email/password login.`,
        emailContent
      );
    } catch (emailError) {
      console.error('Failed to send login notification:', emailError);
    }
    
    res.json({ token, role: matchedUser.role, userId: matchedUser.userId });
  } catch (err) {
    console.error('Error during email login:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/auth/register - Register new user (Admin only)
router.post('/register', verifyToken, restrictTo(['Admin']), async (req, res) => {
  const { fullName, email, password, role, class: studentClass, coursesTeaching, linkedStudentId } = req.body;
  
  try {
    // Validate required fields
    if (!fullName || !email || !role) {
      return res.status(400).json({ error: 'Missing required fields' });
    }
    
    // Role-specific validation
    if (role === 'Student' && !studentClass) {
      return res.status(400).json({ error: 'Class is required for students' });
    }
    
    if (role === 'Teacher' && (!coursesTeaching || !coursesTeaching.length)) {
      return res.status(400).json({ error: 'Courses teaching are required for teachers' });
    }
    
    if (role === 'Parent' && !linkedStudentId) {
      return res.status(400).json({ error: 'Linked student ID is required for parents' });
    }
    
    // Check if a user with this email already exists
    const users = await User.find({});
    for (const user of users) {
      if (user.email && user.email.encryptedData && user.email.iv) {
        try {
          const decryptedEmail = decryptData(user.email.encryptedData, user.email.iv);
          if (decryptedEmail.toLowerCase() === email.toLowerCase()) {
            return res.status(400).json({ error: 'Email already in use' });
          }
        } catch (decryptError) {
          console.error('Failed to decrypt email during registration check:', decryptError);
        }
      }
    }
    
    // Generate userId and QR token
    const userId = `${role.toLowerCase()}-${crypto.randomBytes(4).toString('hex')}`;
    const qrToken = crypto.randomBytes(32).toString('hex');
    
    // Encrypt email
    const { encryptedData, iv } = encryptData(email);
    
    // Create new user object
    const newUser = {
      userId,
      fullName,
      email: { encryptedData, iv },
      password,
      role,
      qrToken,
      class: studentClass,
    };
    
    // Add role-specific data
    if (role === 'Teacher') {
      newUser.coursesTeaching = coursesTeaching;
    }
    
    if (role === 'Parent') {
      // Find linked student
      const student = await User.findOne({ userId: linkedStudentId, role: 'Student' });
      if (!student) {
        return res.status(404).json({ error: 'Linked student not found' });
      }
      
      newUser.linkedStudentData = {
        userId: student.userId,
        fullName: student.fullName,
        class: student.class,
      };
    }
    
    // Create the user
    const user = await User.create(newUser);
    
    // Log creation
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `create_user:${userId}`,
      hash: createHash('sha256').update(`create_user:${userId}`).digest('hex'),
    });
    
    // Send welcome email
    try {
      const emailContent = `
        <h2>Welcome to the Student Data Vault!</h2>
        <p>Hello ${fullName},</p>
        <p>Your account has been created successfully with the role of <strong>${role}</strong>.</p>
        <p>Your User ID is: <strong>${userId}</strong></p>
        <p>Please Recive your Qr Login Card from Admin Office.</p>
        <p>If you have any questions, please contact the administrator.</p>
      `;
      
      await sendEmail(
        email,
        'Welcome to Student Data Vault',
        `Hello ${fullName},\nYour account has been created successfully with the role of ${role}.\nYour User ID is: ${userId}`,
        emailContent
      );
    } catch (emailError) {
      console.error('Failed to send welcome email:', emailError);
    }
    
    res.status(201).json({
      message: 'User created successfully',
      user: {
        userId: user.userId,
        fullName: user.fullName,
        role: user.role,
      }
    });
  } catch (err) {
    console.error('Error registering user:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;