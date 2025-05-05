import { Router } from 'express';
import { createHash } from 'crypto';
import Log from '../models/log.js';
import { verifyToken, restrictTo } from '../middleware/auth.js';

const router = Router();

// GET /api/logs - Get all logs (Admin only)
router.get('/', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    // Parse query parameters for filtering
    const { userId, role, action, from, to, limit =50000 } = req.query;
    
    // Build filter object
    const filter = {};
    if (userId) filter.userId = userId;
    if (role) filter.role = role;
    if (action) filter.action = { $regex: action, $options: 'i' };
    
    // Add date range filter if provided
    if (from || to) {
      filter.timestamp = {};
      if (from) filter.timestamp.$gte = new Date(from);
      if (to) filter.timestamp.$lte = new Date(to);
    }
    
    // Fetch logs with filter and sort by timestamp
    const logs = await Log.find(filter)
      .sort({ timestamp: -1 })
      .limit(parseInt(limit));
    
    // Log this action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'view_logs',
      hash: createHash('sha256').update('view_logs').digest('hex'),
    });
    
    // Send JSON response for API
    res.json(logs);
  } catch (err) {
    console.error('Error fetching logs:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// GET /api/logs/verify - Verify log integrity (Admin only)
router.get('/verify', verifyToken, restrictTo(['Admin']), async (req, res) => {
  try {
    const logs = await Log.find().sort({ timestamp: -1 });
    
    const verificationResults = logs.map(log => {
      // Recreate the expected hash for this action
      const expectedHash = createHash('sha256').update(log.action).digest('hex');
      
      // Check if the stored hash matches the expected hash
      const isValid = expectedHash === log.hash;
      
      return {
        id: log._id,
        userId: log.userId,
        role: log.role,
        action: log.action,
        timestamp: log.timestamp,
        isValid,
        storedHash: log.hash.substring(0, 10) + '...',
        expectedHash: expectedHash.substring(0, 10) + '...',
      };
    });
    
    // Find logs with invalid hashes (potential tampering)
    const invalidLogs = verificationResults.filter(log => !log.isValid);
    
    // Log this verification action
    await Log.create({
      userId: req.user.id,
      role: req.user.role,
      action: 'verify_logs',
      hash: createHash('sha256').update('verify_logs').digest('hex'),
    });
    
    res.json({
      totalLogs: logs.length,
      validLogs: logs.length - invalidLogs.length,
      invalidLogs: invalidLogs.length,
      results: verificationResults,
    });
  } catch (err) {
    console.error('Error verifying logs:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

export default router;