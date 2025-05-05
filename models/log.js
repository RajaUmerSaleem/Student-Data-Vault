import mongoose from 'mongoose';

const logSchema = new mongoose.Schema({
  userId: { type: String, required: true },
  role: { type: String, required: true },
  action: { type: String, required: true },
  timestamp: { type: Date, default: Date.now },
  hash: { type: String, required: true }, 
});

// Export the Log model
const Log = mongoose.models.Log || mongoose.model('Log', logSchema);
export default Log;