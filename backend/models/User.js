// models/User.js
const mongoose = require("mongoose");
const { encryptString } = require("../utils/crypto");

const userSchema = new mongoose.Schema(
  {
    
    username: { type: String, select: false, trim: true },
    email: { type: String, select: false, lowercase: true, trim: true },
    
    emailHash: { type: String, unique: true, index: true, required: true },
    
    usernameEnc: { type: String },
    emailEnc: { type: String },
    password: { type: String, required: false }, 
    isVerified: { type: Boolean, default: false },
    otp: { type: String },
    otpExpiresAt: { type: Date },
    profileImage: { type: String, default: null },
    googleId: { type: String, unique: true, sparse: true }, 
    googleEmail: { type: String, lowercase: true, trim: true },
    googleName: { type: String, trim: true },
    googlePicture: { type: String }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);

// Ensure encrypted mirrors are maintained for username and email
userSchema.pre("save", function(next) {
  try {
    if (this.isModified("username") || this.isNew) {
      if (this.username) this.usernameEnc = encryptString(this.username);
      // Clear plaintext username to avoid storing readable data
      this.username = undefined;
    }
    if (this.isModified("email") || this.isNew) {
      if (this.email) this.emailEnc = encryptString(this.email);
      // Clear plaintext email; emailHash must be set by controllers
      this.email = undefined;
    }
    next();
  } catch (e) {
    next(e);
  }
});
