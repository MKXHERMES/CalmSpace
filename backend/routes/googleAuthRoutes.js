const express = require("express");
const router = express.Router();
const passport = require("passport");
const googleAuthController = require("../controllers/googleAuthController");

// Setup Google OAuth strategy
googleAuthController.setupGoogleStrategy(passport);

// Google OAuth routes
router.get("/google", googleAuthController.googleAuth(passport));
router.get("/google/callback", 
  googleAuthController.googleCallback(passport),
  googleAuthController.googleCallbackHandler
);

// Check if user exists (for registration validation)
router.post("/check-user", googleAuthController.checkUserExists);

// Debug endpoint to check Google users (remove in production)
router.get("/debug/users", async (req, res) => {
  try {
    const User = require("../models/User");
    const googleUsers = await User.find({ googleId: { $exists: true } }).select('username email isVerified googleId googleName googleEmail googlePicture createdAt');
    res.json({ 
      message: "Google users found", 
      count: googleUsers.length,
      users: googleUsers 
    });
  } catch (error) {
    console.error("Debug users error:", error);
    res.status(500).json({ error: "Failed to fetch users" });
  }
});

module.exports = router;
