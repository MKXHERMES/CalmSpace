const mongoose = require("mongoose");

const JournalEntrySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true },
    // Encrypted string payloads (JSON) written by controllers; they are decrypted before responses
    text: { type: String, required: true, trim: true },
    mood: { type: String, required: true },
  },
  { timestamps: true }
);

module.exports = mongoose.model("JournalEntry", JournalEntrySchema);
