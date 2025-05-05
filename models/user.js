import mongoose from 'mongoose';
import bcrypt from 'bcrypt';

// Define courses schema (used for students)
const courseSchema = new mongoose.Schema({
  courseCode: { type: String },
  courseName: { type: String },
  grade: { type: String },
  teacher: { type: String }, // Reference to teacher's userId
});

// Main user schema
const userSchema = new mongoose.Schema({
  userId: { type: String, required: true, unique: true },
  fullName: { type: String, required: true },
  email: {
    encryptedData: { type: String, required: true },
    iv: { type: String, required: true },
  },
  password: { type: String }, // Added for email/password login
  role: { type: String, required: true, enum: ['Admin', 'Teacher', 'Student', 'Parent'] },
  qrToken: { type: String, required: true },
  class: { type: String }, // For students
  courses: [courseSchema], // Array of courses for students
  coursesTeaching: [String], // For teachers - array of course codes they teach
  linkedStudentData: { // For parents
    userId: { type: String },
    fullName: { type: String },
    class: { type: String },
  },
  deletionRequested: { type: Boolean, default: false },
  lastLogin: { type: Date },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (this.password && this.isModified('password')) {
    try {
      const salt = await bcrypt.genSalt(10);
      this.password = await bcrypt.hash(this.password, salt);
    } catch (err) {
      return next(err);
    }
  }
  
  if (this.isModified()) {
    this.updatedAt = Date.now();
  }
  
  next();
});

// Method to compare passwords
userSchema.methods.comparePassword = async function(candidatePassword) {
  if (!this.password) return false;
  return bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

export default User;