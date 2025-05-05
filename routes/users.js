import express from 'express';
import crypto from 'crypto';
import qrcode from 'qrcode';
import User from '../models/user.js';
import Log from '../models/log.js';
import { verifyToken, restrictTo } from '../middleware/auth.js';
import { sendEmail } from '../utils/email.js';

const router = express.Router();

const AES_KEY  =  Buffer.from('0123456789abcdef0123456789abcdef');
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

// ADMIN ENDPOINTS
// GET /api/users - Get all users (Admin only)
router.get('/', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    const users = await User.find({}).sort({ createdAt: -1 });
    
    const processedUsers = users.map(user => {
      const userData = user.toObject();
      
      // Try to decrypt email
      if (userData.email && userData.email.encryptedData && userData.email.iv) {
        try {
          userData.decryptedEmail = decryptData(userData.email.encryptedData, userData.email.iv);
        } catch (err) {
          userData.decryptedEmail = 'Unable to decrypt';
        }
      }
      
      delete userData.password;
      return userData;
    });
    
    // Log this action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'view_all_users',
      hash: crypto.createHash('sha256').update('view_all_users').digest('hex'),
    });
    
    res.json(processedUsers);
  } catch (err) {
    console.error('Error fetching users:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users/:id - Get user by ID (Admin only)
router.get('/:id', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.params.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    const userData = user.toObject();
    
    // Try to decrypt email
    if (userData.email && userData.email.encryptedData && userData.email.iv) {
      try {
        userData.decryptedEmail = decryptData(userData.email.encryptedData, userData.email.iv);
      } catch (err) {
        userData.decryptedEmail = 'Unable to decrypt';
      }
    }
    
    // Remove sensitive data
    delete userData.password;
    
    // Log this action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `view_user:${req.params.id}`,
      hash: crypto.createHash('sha256').update(`view_user:${req.params.id}`).digest('hex'),
    });
    
    res.json(userData);
  } catch (err) {
    console.error('Error fetching user:', err);
    res.status(500).json({ error: 'Server error' });
  }
});


// GET /api/users/id-card/:id - Generate ID card with QR code (Admin only)
router.get('/id-card/:id', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.params.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    console.log(user.qrToken)
    // Log this action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `generate_id_card:${req.params.id}`,
      hash: crypto.createHash('sha256').update(`generate_id_card:${req.params.id}`).digest('hex'),
    });
    
    // Prepare card data
    const cardData = {
      userId: user.userId,
      fullName: user.fullName,
      role: user.role,
      qrCode: user.qrToken,
      class: user.class || '',
      issuedDate: new Date().toLocaleDateString(),
      institution: 'Student Data Vault',
    };
    
    // Create a template for the HTML ID card
    const idCardHtml = `
      <div class="card-container">
        <div class="id-card">
          <div class="header">
            <h2>Student Data Vault</h2>
            <h3>${user.role} ID Card</h3>
          </div>
          <div class="photo-container">
            <div class="photo">
            </div>
          </div>
          <div class="details">
            <p><strong>ID:</strong> ${user.userId}</p>
            <p><strong>Name:</strong> ${user.fullName}</p>
            <p><strong>Role:</strong> ${user.role}</p>
            ${user.class ? `<p><strong>Class:</strong> ${user.class}</p>` : ''}
            <p><strong>Issued:</strong> ${new Date().toLocaleDateString()}</p>
          </div>
          <div class="qr-code">
            <img src="https://api.qrserver.com/v1/create-qr-code/?data=${user.qrToken}" alt="QR Code" />
            <p>Scan for authentication</p>
          </div>
          <div class="footer">
            <p>This ID card is property of Student Data Vault</p>
          </div>
        </div>
      </div>
      <style>
        .card-container {
          display: flex;
          justify-content: center;
          font-family: Arial, sans-serif;
        }
        .id-card {
          width: 330px;
          height: 500px;
          background: #fff;
          border-radius: 10px;
          box-shadow: 0 0 10px rgba(0,0,0,0.2);
          padding: 20px;
          display: flex;
          flex-direction: column;
          overflow: hidden;
          color: #333;
        }
        .header {
          text-align: center;
          margin-bottom: 10px;
          border-bottom: 2px solid #1a73e8;
          padding-bottom: 10px;
        }
        .header h2 {
          margin: 0;
          color: #1a73e8;
          font-size: 20px;
        }
        .header h3 {
          margin: 5px 0 0;
          color: #333;
          font-size: 16px;
        }
        .photo-container {
          display: flex;
          justify-content: center;
          margin: 10px 0;
        }
        .photo {
          width: 100px;
          height: 100px;
          overflow: hidden;
          border-radius: 50%;
          border: 3px solid rgba(26, 115, 232, 0.17);
          background:rgb(0, 255, 76);
        }
        .photo img {
          width: 100%;
          height: auto;
        }
        .details {
          margin: 15px 0;
        }
        .details p {
          margin: 5px 0;
          font-size: 14px;
        }
        .qr-code {
          text-align: center;
          margin: 15px 0;
        }
        .qr-code img {
          width: 120px;
          height: 120px;
        }
        .qr-code p {
          margin: 5px 0;
          font-size: 12px;
          color: #666;
        }
        .footer {
          margin-top: auto;
          text-align: center;
          border-top: 1px solid #ddd;
          padding-top: 10px;
          font-size: 10px;
          color: #666;
        }
        @media print {
          body {
            margin: 0;
            padding: 0;
          }
          .card-container {
            width: 100%;
            height: 100%;
          }
          .id-card {
            box-shadow: none;
            border: 1px solid #ddd;
          }
        }
      </style>
    `;
    
    // Return both JSON and HTML
    res.json({
      ...cardData,
      html: idCardHtml
    });
  } catch (err) {
    console.error('Error generating ID card:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PUT /api/users/:id - Update user (Admin only)
router.put('/:id', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    const { fullName, email, role, class: studentClass, coursesTeaching, password } = req.body;
    
    // Find user
    const user = await User.findOne({ userId: req.params.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Update fields if provided
    if (fullName) user.fullName = fullName;
    if (studentClass) user.class = studentClass;
    if (coursesTeaching) user.coursesTeaching = coursesTeaching;
    
    // Only update role if changing between valid roles
    if (role && ['Admin', 'Teacher', 'Student', 'Parent'].includes(role)) {
      user.role = role;
    }
    
    // Handle email update (requires encryption)
    if (email) {
      const { encryptedData, iv } = encryptData(email);
      user.email = { encryptedData, iv };
    }
    
    if (password) {
      user.password = password; 
      await Log.create({
        userId: req.user.id,
        role: req.user.role,
        action: `reset_password:${req.params.id}`,
        hash: crypto.createHash('sha256').update(`reset_password:${req.params.id}`).digest('hex'),
      });
    }
    
    // Save the updated user
    await user.save();
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `update_user:${req.params.id}`,
      hash: crypto.createHash('sha256').update(`update_user:${req.params.id}`).digest('hex'),
    });
    
    // Try to send notification email
    try {
      if (user.email && user.email.encryptedData && user.email.iv) {
        const userEmail = decryptData(user.email.encryptedData, user.email.iv);
        
        let emailContent = `
          <h2>Account Update Notification</h2>
          <p>Hello ${user.fullName},</p>
          <p>Your account information has been updated by an administrator.</p>
        `;
        
        // Add password change notification if applicable
        if (password) {
          emailContent += `<p><strong>Your password has been reset.</strong> If you did not request this change, please contact support immediately.</p>`;
        } else {
          emailContent += `<p>If you did not expect this change, please contact Admin.</p>`;
        }
        
        await sendEmail(
          userEmail,
          'Account Update Notification',
          `Hello ${user.fullName},\nYour account information has been updated by an administrator.`,
          emailContent
        );
      }
    } catch (emailErr) {
      console.error('Failed to send update notification:', emailErr);
    }
    
    res.json({ message: 'User updated successfully' });
  } catch (err) {
    console.error('Error updating user:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// DELETE /api/users/:id - Delete user (Admin only)
router.delete('/:id', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.params.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Try to send notification before deletion
    try {
      if (user.email && user.email.encryptedData && user.email.iv) {
        const userEmail = decryptData(user.email.encryptedData, user.email.iv);
        
        const emailContent = `
          <h2>Account Deletion Notification</h2>
          <p>Hello ${user.fullName},</p>
          <p>Your account has been deleted from the Student Data Vault system.</p>
          <p>If you did not expect this action, please contact support.</p>
        `;
        
        await sendEmail(
          userEmail,
          'Account Deletion Notification',
          `Hello ${user.fullName},\nYour account has been deleted from the Student Data Vault system.`,
          emailContent
        );
      }
    } catch (emailErr) {
      console.error('Failed to send deletion notification:', emailErr);
    }
    
    // Delete the user
    await User.findOneAndDelete({ userId: req.params.id });
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `delete_user:${req.params.id}`,
      hash: crypto.createHash('sha256').update(`delete_user:${req.params.id}`).digest('hex'),
    });
    
    res.json({ message: 'User deleted successfully' });
  } catch (err) {
    console.error('Error deleting user:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/users/generate-qr/:id - Generate new QR code (Admin only)
router.post('/generate-qr/:id', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    const user = await User.findOne({ userId: req.params.id });
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Generate new QR token
    const newQrToken = crypto.randomBytes(32).toString('hex');
    user.qrToken = newQrToken;
    await user.save();
    
    // Generate QR code image
   await qrcode.toDataURL(newQrToken);
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `generate_qr:${req.params.id}`,
      hash: crypto.createHash('sha256').update(`generate_qr:${req.params.id}`).digest('hex'),
    });
    
    // Try to send QR code by email
    try {
      if (user.email && user.email.encryptedData && user.email.iv) {
        const userEmail = decryptData(user.email.encryptedData, user.email.iv);
        
        const emailContent = `
          <h2>Your New QR Code</h2>
          <p>Hello ${user.fullName},</p>
          <p>A new QR code has been generated for your account, Take your Card from Admin Office</p>
          <p>If you did not request this change, please contact support immediately.</p>
        `;
        
        await sendEmail(
          userEmail,
          'Your New QR Code',
          `Hello ${user.fullName},\nA new QR code has been generated for your account.`,
          emailContent
        );
      }
    } catch (emailErr) {
      console.error('Failed to send QR code email:', emailErr);
    }
    
    res.json({ message: 'New QR code generated successfully', qrToken: newQrToken });
  } catch (err) {
    console.error('Error generating QR code:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// STUDENT ENDPOINTS
function getCourseNameByCode(code) {
  // This is a simplified version - you might want to store this in your database
  const courseMap = {
    'Math101': 'Calculus I',
    'Math102': 'Linear Algebra',
    'CS101': 'Introduction to Computer Science',
    'PF502': 'Programming Fundamentals',
    'AI301': 'Artificial Intelligence',
    'DB202': 'Database Systems',
    'ML401': 'Machine Learning',
  };
  
  return courseMap[code] || code; // Return the name or the code if not found
}
// POST /api/users/register-courses - Register for courses (Student only)
router.patch('/register-courses', verifyToken, restrictTo(['Student']), async (req, res) => {
  try {
    const { courses } = req.body;
    
    if (!courses || !Array.isArray(courses) || !courses.length) {
      return res.status(400).json({ error: 'Valid courses array is required' });
    }
    
    const user = await User.findOne({ userId: req.user.id, role: 'Student' });
    if (!user) return res.status(404).json({ error: 'Student not found' });
    
    // Initialize courses array if it doesn't exist
    if (!user.courses) {
      user.courses = [];
    }
    
    // Format new courses
    const newFormattedCourses = courses.map(course => ({
      courseCode: course.courseCode,
      courseName: course.courseName,
      teacher: course.teacher,
      grade: 'Not graded'
    }));
    
    // Check for duplicates before adding
    for (const newCourse of newFormattedCourses) {
      // Check if course already exists
      const existingCourseIndex = user.courses.findIndex(
        c => c.courseCode === newCourse.courseCode
      );
      
      if (existingCourseIndex >= 0) {
        // Course already exists, update it
        user.courses[existingCourseIndex] = newCourse;
      } else {
        // Course doesn't exist, add it
        user.courses.push(newCourse);
      }
    }
    
    // Save updated user with appended courses
    await user.save();
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'register_courses',
      hash: crypto.createHash('sha256').update('register_courses').digest('hex'),
    });
    
    res.json({ 
      message: 'Courses registered successfully', 
      courses: user.courses 
    });
  } catch (err) {
    console.error('Error registering courses:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
// GET /api/users/available-courses - Get all available courses for registration (Student only)
router.get('/courses/available', verifyToken, restrictTo(['Student']), async (req, res) => {
  try {
    // Find all teachers
    const teachers = await User.find({ role: 'Teacher' });
    
    // Prepare available courses list
    const availableCourses = [];
    
    // For each teacher, extract their courses
    for (const teacher of teachers) {
      if (teacher.coursesTeaching && Array.isArray(teacher.coursesTeaching)) {
        // For each course this teacher teaches
        for (const courseCode of teacher.coursesTeaching) {
          // Add course details to the list
          availableCourses.push({
            courseCode,
            // You might want to add a mapping of course codes to course names
            courseName: getCourseNameByCode(courseCode),
            teacher: teacher.userId,
            teacherName: teacher.fullName
          });
        }
      }
    }
    
    // Log this action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'view_available_courses',
      hash: crypto.createHash('sha256').update('view_available_courses').digest('hex'),
    });
    
    res.json(availableCourses);
  } catch (err) {
    console.error('Error fetching available courses:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// POST /api/users/delete - Request account deletion (Student only)
router.post('/delete', verifyToken, restrictTo(['Student']), async (req, res) => {
  try {
    const user = await User.findOneAndUpdate(
      { userId: req.user.id, role: 'Student' },
      { deletionRequested: true },
      { new: true }
    );
    
    if (!user) return res.status(404).json({ error: 'User not found' });
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'request_deletion',
      hash: crypto.createHash('sha256').update('request_deletion').digest('hex'),
    });
    
    // Send notification to admin
    try {
      const admins = await User.find({ role: 'Admin' });
      
      for (const admin of admins) {
        if (admin.email && admin.email.encryptedData && admin.email.iv) {
          const adminEmail = decryptData(admin.email.encryptedData, admin.email.iv);
          
          const emailContent = `
            <h2>GDPR Request Notification</h2>
            <p>Hello Administrator,</p>
            <p>Student ${user.fullName} (${user.userId}) has requested For viewing my data.</p>
            <p>Please review this request,.</p>
          `;
          
          await sendEmail(
            adminEmail,
            'Account GDPR Request',
            `Student ${user.fullName} (${user.userId}) has requested for GDPR.`,
            emailContent
          );
        }
      }
    } catch (emailErr) {
      console.error('Failed to send deletion request notification:', emailErr);
    }
    
    res.json({ message: 'Deletion request submitted successfully' });
  } catch (err) {
    console.error('Error requesting deletion:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
// GET /api/users/meraresult - Get student's own grades (Student only)
router.get('/result/result', verifyToken, restrictTo(['Student']), async (req, res) => {
  try {
    const student = await User.findOne({ userId: req.user.id, role: 'Student' });
    if (!student) return res.status(404).json({ error: 'Student not found' });
    
    // Extract courses with grades
    const coursesWithGrades = student.courses || [];
    
    // Format course data for better readability
    const formattedCourses = coursesWithGrades.map(course => {
      return {
        courseCode: course.courseCode,
        courseName: course.courseName || getCourseNameByCode(course.courseCode),
        teacher: course.teacher, // This could be improved to show teacher name instead of ID
        grade: course.grade || 'Not graded yet'
      };
    });
    
    // Log this action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'view_own_grades',
      hash: crypto.createHash('sha256').update('view_own_grades').digest('hex'),
    });
    
    res.json({
      studentId: student.userId,
      studentName: student.fullName,
      class: student.class,
      courses: formattedCourses
    });
  } catch (err) {
    console.error('Error fetching student grades:', err);
    res.status(500).json({ error: 'Server error' });
  }
});
// TEACHER ENDPOINTS

// GET /api/users/courses/teaching - Get courses teaching (Teacher only)
router.get('/courses/teaching', verifyToken, restrictTo(['Teacher']), async (req, res) => {
  try {
    const teacher = await User.findOne({ userId: req.user.id, role: 'Teacher' });
    if (!teacher) return res.status(404).json({ error: 'Teacher not found' });
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'view_teaching_courses',
      hash: crypto.createHash('sha256').update('view_teaching_courses').digest('hex'),
    });
    
    res.json(teacher.coursesTeaching || []);
  } catch (err) {
    console.error('Error fetching teaching courses:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/users/courses/:courseCode/students - Get students in a course (Teacher only)
router.get('/courses/:courseCode/students', verifyToken, restrictTo(['Teacher']), async (req, res) => {
  try {
    const { courseCode } = req.params;
    
    // Verify teacher teaches this course
    const teacher = await User.findOne({ 
      userId: req.user.id, 
      role: 'Teacher', 
      coursesTeaching: { $in: [courseCode] } 
    });
    
    if (!teacher) {
      return res.status(403).json({ 
        error: 'You are not authorized to view students for this course' 
      });
    }
    
    // Find students enrolled in this course
    const students = await User.find({ 
      role: 'Student', 
      'courses.courseCode': courseCode 
    });
    
    // Format student data
    const formattedStudents = students.map(student => {
      const course = student.courses.find(c => c.courseCode === courseCode);
      return {
        userId: student.userId,
        fullName: student.fullName,
        class: student.class,
        grade: course ? course.grade : 'Not graded'
      };
    });
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `view_course_students:${courseCode}`,
      hash: crypto.createHash('sha256').update(`view_course_students:${courseCode}`).digest('hex'),
    });
    
    res.json(formattedStudents);
  } catch (err) {
    console.error('Error fetching course students:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PATCH /api/users/:id/grades - Update student grades (Teacher only)
router.patch('/:id/grades', verifyToken, restrictTo(['Teacher']), async (req, res) => {
  try {
    const { courseCode, grade } = req.body;
    
    if (!courseCode || !grade) {
      return res.status(400).json({ error: 'Course code and grade are required' });
    }
    
    // Verify teacher teaches this course
    const teacher = await User.findOne({ 
      userId: req.user.id, 
      role: 'Teacher', 
      coursesTeaching: { $in: [courseCode] } 
    });
    
    if (!teacher) {
      return res.status(403).json({ 
        error: 'You are not authorized to update grades for this course' 
      });
    }
    
    // Find the student
    const student = await User.findOne({ 
      userId: req.params.id, 
      role: 'Student', 
      'courses.courseCode': courseCode 
    });
    
    if (!student) {
      return res.status(404).json({ 
        error: 'Student not found or not enrolled in this course' 
      });
    }
    
    // Update the grade
    const updatedStudent = await User.findOneAndUpdate(
      { userId: req.params.id, 'courses.courseCode': courseCode },
      { $set: { 'courses.$.grade': grade } },
      { new: true }
    );
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: `update_grade:${req.params.id}:${courseCode}`,
      hash: crypto.createHash('sha256').update(`update_grade:${req.params.id}:${courseCode}`).digest('hex'),
    });
    
    // Try to notify the student
    try {
      if (student.email && student.email.encryptedData && student.email.iv) {
        const studentEmail = decryptData(student.email.encryptedData, student.email.iv);
        
        const emailContent = `
          <h2>Grade Update Notification</h2>
          <p>Hello ${student.fullName},</p>
          <p>Your grade for ${courseCode} has been updated to: <strong>${grade}</strong></p>
          <p>If you have any questions, please contact your teacher.</p>
        `;
        
        await sendEmail(
          studentEmail,
          'Grade Update Notification',
          `Hello ${student.fullName},\nYour grade for ${courseCode} has been updated to: ${grade}`,
          emailContent
        );
      }
    } catch (emailErr) {
      console.error('Failed to send grade update notification:', emailErr);
    }
    
    // Try to notify the parent
    try {
      const parent = await User.findOne({
        role: 'Parent',
        'linkedStudentData.userId': student.userId
      });
      
      if (parent && parent.email && parent.email.encryptedData && parent.email.iv) {
        const parentEmail = decryptData(parent.email.encryptedData, parent.email.iv);
        
        const emailContent = `
          <h2>Grade Update Notification</h2>
          <p>Hello ${parent.fullName},</p>
          <p>Your child's (${student.fullName}) grade for ${courseCode} has been updated to: <strong>${grade}</strong></p>
          <p>If you have any questions, please contact the teacher.</p>
        `;
        
        await sendEmail(
          parentEmail,
          'Child\'s Grade Update Notification',
          `Hello ${parent.fullName},\nYour child's (${student.fullName}) grade for ${courseCode} has been updated to: ${grade}`,
          emailContent
        );
      }
    } catch (emailErr) {
      console.error('Failed to send parent grade notification:', emailErr);
    }
    
    res.json({ message: 'Grade updated successfully' });
  } catch (err) {
    console.error('Error updating grade:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// PARENT ENDPOINTS

// GET /api/users/parent/student - Get linked student's data (Parent only)
router.get('/parent/student', verifyToken, restrictTo(['Parent']), async (req, res) => {
  try {
    // Find the parent
    const parent = await User.findOne({ userId: req.user.id, role: 'Parent' });
    if (!parent) return res.status(404).json({ error: 'Parent not found' });
    
    // Ensure parent has linked student data
    if (!parent.linkedStudentData || !parent.linkedStudentData.userId) {
      return res.status(404).json({ error: 'No linked student found' });
    }
    
    // Find the linked student
    const student = await User.findOne({ 
      userId: parent.linkedStudentData.userId, 
      role: 'Student' 
    });
    
    if (!student) {
      return res.status(404).json({ error: 'Linked student not found' });
    }
    
    // Format student data for parent view
    const studentData = {
      userId: student.userId,
      fullName: student.fullName,
      class: student.class,
      courses: student.courses || []
    };
    
    // Log the action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'view_child_data',
      hash: crypto.createHash('sha256').update('view_child_data').digest('hex'),
    });
    
    res.json(studentData);
  } catch (err) {
    console.error('Error fetching student data for parent:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;