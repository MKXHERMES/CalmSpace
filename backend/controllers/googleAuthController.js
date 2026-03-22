const User = require("../models/User");
const jwt = require("jsonwebtoken");
const { encryptString, hmacDeterministic } = require("../utils/crypto");

// Generate JWT token
const generateToken = (userId, email) => {
  return jwt.sign({ id: userId, email: email }, process.env.JWT_SECRET, { expiresIn: "7d" });
};

// Google OAuth strategy setup
exports.setupGoogleStrategy = (passport) => {
  // Check if Google OAuth credentials are available
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    console.warn("⚠️  Google OAuth credentials not found. Google sign-in will be disabled.");
    console.warn("   To enable Google OAuth, set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET in your environment variables.");
    return; // Exit early if credentials are missing
  }

  const GoogleStrategy = require("passport-google-oauth20").Strategy;

  passport.use(
    new GoogleStrategy(
      {
        clientID: process.env.GOOGLE_CLIENT_ID,
        clientSecret: process.env.GOOGLE_CLIENT_SECRET,
        callbackURL: "/api/auth/google/callback",
      },
      async (accessToken, refreshToken, profile, done) => {
        try {
          console.log("🔍 Google OAuth Profile:", {
            id: profile.id,
            displayName: profile.displayName,
            email: profile.emails?.[0]?.value,
            photo: profile.photos?.[0]?.value
          });

          // Check if user already exists with this Google ID
          let user = await User.findOne({ googleId: profile.id });

          

          // Check if user exists with the same email but different auth method
          const existingUser = await User.findOne({ emailHash: hmacDeterministic(profile.emails[0].value) });
          
          if (existingUser) {
            console.log("🔗 Linking Google account to existing user");
            // Link Google account to existing user
            existingUser.googleId = profile.id;
            existingUser.googleEmail = profile.emails[0].value;
            existingUser.googleName = profile.displayName;
            existingUser.googlePicture = profile.photos[0]?.value;
            existingUser.isVerified = true; 
            existingUser.usernameEnc = encryptString(profile.displayName || existingUser.googleName || "");
            existingUser.emailEnc = encryptString(profile.emails[0].value);
            await existingUser.save();
            console.log("✅ Google account linked successfully");
            return done(null, existingUser);
          }

          // Create new user with Google OAuth
          console.log("🆕 Creating new Google user");
          const newUser = new User({
            emailHash: hmacDeterministic(profile.emails[0].value),
            googleId: profile.id,
            googleEmail: profile.emails[0].value,
            googleName: profile.displayName,
            googlePicture: profile.photos[0]?.value,
            isVerified: true, 
            usernameEnc: encryptString(profile.displayName || profile.emails[0].value.split("@")[0]),
            emailEnc: encryptString(profile.emails[0].value),
          });

          await newUser.save();
          console.log("✅ New Google user created:", newUser.email, "isVerified:", newUser.isVerified);
          return done(null, newUser);
        } catch (error) {
          console.error("❌ Google OAuth error:", error);
          return done(error, null);
        }
      }
    )
  );


  passport.serializeUser((user, done) => {
    done(null, user._id);
  });

  
  passport.deserializeUser(async (id, done) => {
    try {
      const user = await User.findById(id);
      done(null, user);
    } catch (error) {
      done(error, null);
    }
  });
};

// Google OAuth routes
exports.googleAuth = (passport) => {
  
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return (req, res) => {
      res.redirect(`${process.env.FRONTEND_URL || "http://localhost:3000"}/login?error=google_auth_not_configured`);
    };
  }
  
  return passport.authenticate("google", {
    scope: ["profile", "email"],
  });
};

exports.googleCallback = (passport) => {
  
  if (!process.env.GOOGLE_CLIENT_ID || !process.env.GOOGLE_CLIENT_SECRET) {
    return (req, res) => {
      res.redirect(`${process.env.FRONTEND_URL || "http://localhost:3000"}/login?error=google_auth_not_configured`);
    };
  }
  
  return passport.authenticate("google", {
    failureRedirect: `${process.env.FRONTEND_URL || "http://localhost:3000"}/login?error=google_auth_failed`,
  });
};

exports.googleCallbackHandler = async (req, res) => {
  try {
    const user = req.user;
    
    if (!user) {
      console.log("❌ No user found in Google callback");
      return res.redirect(`${process.env.FRONTEND_URL || "http://localhost:3000"}/login?error=google_auth_failed`);
    }

    console.log("🎉 Google OAuth successful for user:", {
      id: user._id,
      username: user.username,
      email: user.email,
      isVerified: user.isVerified,
      googleId: user.googleId,
      googleName: user.googleName
    });

    // Generate JWT token
    const token = generateToken(user._id, user.email);

    
    res.cookie(process.env.COOKIE_NAME || "token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 7 * 24 * 60 * 60 * 1000, // 7 days
    });

    console.log("✅ JWT token generated and cookie set, redirecting to home");
    console.log("🔑 Token payload:", { id: user._id, email: user.email });
    
    res.redirect(`${process.env.FRONTEND_URL || "http://localhost:3000"}/home`);
  } catch (error) {
    console.error("❌ Google callback handler error:", error);
    res.redirect(`${process.env.FRONTEND_URL || "http://localhost:3000"}/login?error=google_auth_failed`);
  }
};


exports.checkUserExists = async (req, res) => {
  try {
    const { email } = req.body;
    
    if (!email) {
      return res.status(400).json({ message: "Email is required" });
    }

    const user = await User.findOne({ email: email.toLowerCase() });
    
    res.json({ 
      exists: !!user,
      message: user ? "User exists" : "User not found"
    });
  } catch (error) {
    console.error("Check user exists error:", error);
    res.status(500).json({ message: "Server error" });
  }
};
