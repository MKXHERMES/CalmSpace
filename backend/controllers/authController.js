// controllers/authController.js
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const User = require("../models/User");
const generateOTP = require("../utils/generateOTP");
const { sendEmail } = require("../utils/sendEmail");
const { encryptString, decryptString, hmacDeterministic } = require("../utils/crypto");

const SALT_ROUNDS = 10;

exports.register = async (req, res) => {
  try {
    const { username, email, password } = req.body;
    if (!username || !email || !password)
      return res.status(400).json({ message: "All fields are required" });

    const existing = await User.findOne({ emailHash: hmacDeterministic(email) });
    if (existing) return res.status(400).json({ message: "Email already registered" });

    const hashed = await bcrypt.hash(password, SALT_ROUNDS);
    const otp = generateOTP();
    const otpExpiresAt = new Date(Date.now() + 10 * 60 * 1000); 

    const user = new User({
      emailHash: hmacDeterministic(email),
      password: hashed,
      otp,
      otpExpiresAt,
      isVerified: false,
      usernameEnc: encryptString(username),
      emailEnc: encryptString(email),
    });

    await user.save();

    try {
      const subject = "Your verification code";
      const text = `Your OTP is ${otp}. It expires in 10 minutes.`;
      const html = `<p>Your OTP is <b>${otp}</b>. It expires in 10 minutes.</p>`;
      await sendEmail({ to: email, subject, text, html });
    } catch (emailErr) {
      console.error("Failed to send OTP email:", emailErr);
      // Do not expose internal errors
    }

    return res.status(201).json({ message: "Registered. Verification code sent to your email." });
  } catch (err) {
    console.error("Register error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.verifyOTP = async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });

    const user = await User.findOne({ emailHash: hmacDeterministic(email) });
    if (!user) return res.status(400).json({ message: "User not found" });
    if (user.isVerified) return res.status(400).json({ message: "User already verified" });

    if (!user.otp || !user.otpExpiresAt) return res.status(400).json({ message: "No OTP found for user" });

    if (user.otpExpiresAt < new Date()) {
      return res.status(400).json({ message: "OTP expired. Please register again to get a new OTP." });
    }

    if (user.otp !== otp) return res.status(400).json({ message: "Incorrect OTP" });

    user.isVerified = true;
    user.otp = undefined;
    user.otpExpiresAt = undefined;
    await user.save();

    return res.json({ message: "Verified. You can now log in." });
  } catch (err) {
    console.error("Verify OTP error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const user = await User.findOne({ emailHash: hmacDeterministic(email) });
    if (!user) return res.status(400).json({ message: "Invalid credentials" });
    if (!user.isVerified) return res.status(403).json({ message: "Email not verified. Please verify OTP first." });

    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(400).json({ message: "Invalid credentials" });

    
    const payload = { id: user._id };
    const token = jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || "7d" });

   
    res.cookie(process.env.COOKIE_NAME || "token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24 * 7 
    });

    return res.json({ message: "Logged in" });
  } catch (err) {
    console.error("Login error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.logout = async (req, res) => {
  res.clearCookie(process.env.COOKIE_NAME || "token");
  return res.json({ message: "Logged out" });
};

exports.protected = async (req, res) => {
  
  try {
    const user = await User.findById(req.user.id).select('-password -otp -otpExpiresAt');
    if (!user) return res.status(404).json({ message: "User not found" });
    const safeUser = user.toObject();
    
    // Try to decrypt username and email
    let decryptedUsername = user.usernameEnc ? decryptString(user.usernameEnc) : null;
    let decryptedEmail = user.emailEnc ? decryptString(user.emailEnc) : null;
    
    
    if (!decryptedUsername && user.googleName) {
      decryptedUsername = user.googleName;
      // Re-encrypt with new keys for future use
      try {
        user.usernameEnc = encryptString(user.googleName);
        user.username = user.googleName; 
        await user.save();
      } catch (e) {
        console.warn("Failed to re-encrypt username:", e.message);
      }
    }
    
    if (!decryptedEmail && user.googleEmail) {
      decryptedEmail = user.googleEmail;
      
      try {
        user.emailEnc = encryptString(user.googleEmail);
        user.email = user.googleEmail; 
        await user.save();
      } catch (e) {
        console.warn("Failed to re-encrypt email:", e.message);
      }
    }
    
    // Set the values, using Google data as fallback if decryption failed
    safeUser.username = decryptedUsername || user.googleName || undefined;
    safeUser.email = decryptedEmail || user.googleEmail || undefined;
    
    
    delete safeUser.usernameEnc;
    delete safeUser.emailEnc;
    delete safeUser.googleId;
    delete safeUser.googleEmail;
    delete safeUser.googleName;
    
    return res.json({ message: "Protected data", user: safeUser });
  } catch (err) {
    console.error("Protected error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.updateProfile = async (req, res) => {
  try {
    const { username, email } = req.body;
    const userId = req.user.id;

    if (!username && !email) {
      return res.status(400).json({ message: "At least one field is required" });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Check if email is being changed 
    if (email) {
      const newHash = hmacDeterministic(email);
      const existingUser = await User.findOne({ emailHash: newHash });
      if (existingUser && String(existingUser._id) !== String(userId)) {
        return res.status(400).json({ message: "Email already in use" });
      }
    }

    // Update fields
    if (username) {
      user.username = username;
      user.usernameEnc = encryptString(username);
    }
    if (email) {
      user.email = email; // used by pre-save to compute enc, then cleared
      user.emailEnc = encryptString(email);
      user.emailHash = hmacDeterministic(email);
    }

    await user.save();

    
    const updatedUser = await User.findById(userId).select('-password -otp -otpExpiresAt -googleId -googleEmail -googleName');
    const safeUpdated = updatedUser.toObject();
    const decryptedUsername = updatedUser.usernameEnc ? decryptString(updatedUser.usernameEnc) : null;
    const decryptedEmail = updatedUser.emailEnc ? decryptString(updatedUser.emailEnc) : null;
    safeUpdated.username = decryptedUsername || undefined;
    safeUpdated.email = decryptedEmail || undefined;
    delete safeUpdated.usernameEnc;
    delete safeUpdated.emailEnc;
    
    return res.json({ 
      message: "Profile updated successfully", 
      user: safeUpdated 
    });
  } catch (err) {
    console.error("Update profile error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.deleteProfile = async (req, res) => {
  try {
    const userId = req.user.id;
    
    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }

    // Delete the user
    await User.findByIdAndDelete(userId);

    // Clear the cookie
    res.clearCookie(process.env.COOKIE_NAME || "token");

    return res.json({ message: "Account deleted successfully" });
  } catch (err) {
    console.error("Delete profile error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};
