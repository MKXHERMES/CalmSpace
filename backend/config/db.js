const mongoose = require("mongoose");

const connectDB = async () => {
  try {
    
    const uri = process.env.MONGO_URI || "mongodb+srv://yashdharamshi1810_db_user:nLO3BoTqn4WQMzhO@pbl.4bbqt74.mongodb.net/?retryWrites=true&w=majority&appName=PBL";
    
    console.log("🔗 Connecting to MongoDB...");
    console.log("📍 Using URI:", uri.includes('mongodb+srv://') ? 'MongoDB Atlas' : 'Local MongoDB');
    
    await mongoose.connect(uri); 

    console.log("✅ MongoDB Atlas connected successfully");
    console.log("🌐 Database:", mongoose.connection.db.databaseName);

    
    try {
      const User = mongoose.connection.collection("users");
      await User.dropIndex("email_1");
      console.log("✅ Dropped email_1 unique index (using emailHash for uniqueness instead)");
    } catch (indexErr) {
      
      if (indexErr.code !== 27 && indexErr.codeName !== "IndexNotFound") {
        console.warn("⚠️  Warning: Could not drop email_1 index:", indexErr.message);
      }
    }
  } catch (err) {
    console.error("❌ MongoDB connection error:", err.message);
    throw err; 
  }
};

module.exports = connectDB;
