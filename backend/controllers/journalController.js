const JournalEntry = require("../models/JournalEntry");
const { encryptString, decryptString } = require("../utils/crypto");

exports.createEntry = async (req, res) => {
  try {
    const { text, mood } = req.body;
    if (!text || !mood) return res.status(400).json({ message: "Text and mood are required" });

    const entry = await JournalEntry.create({
      user: req.user.id,
      text: encryptString(text),
      mood: encryptString(mood),
    });
    const safe = {
      ...entry.toObject(),
      text,
      mood,
    };
    return res.status(201).json({ message: "Entry created", entry: safe });
  } catch (err) {
    console.error("Create entry error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.listEntries = async (req, res) => {
  try {
    const entries = await JournalEntry.find({ user: req.user.id }).sort({ createdAt: -1 });
    const decrypted = entries.map((e) => {
      const obj = e.toObject();
      obj.text = decryptString(obj.text) || "[Unable to decrypt - encrypted with different keys]";
      obj.mood = decryptString(obj.mood) || "unknown";
      return obj;
    });
    return res.json({ entries: decrypted });
  } catch (err) {
    console.error("List entries error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.updateEntry = async (req, res) => {
  try {
    const { id } = req.params;
    const { text, mood } = req.body;
    
    const entry = await JournalEntry.findById(id);
    if (!entry) return res.status(404).json({ message: "Entry not found" });
    if (String(entry.user) !== String(req.user.id)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    
    // Update only provided fields
    if (text !== undefined) entry.text = encryptString(text);
    if (mood !== undefined) entry.mood = encryptString(mood);
    
    await entry.save();
    const safe = {
      ...entry.toObject(),
      text: text !== undefined ? text : (decryptString(entry.text) || "[Unable to decrypt - encrypted with different keys]"),
      mood: mood !== undefined ? mood : (decryptString(entry.mood) || "unknown"),
    };
    return res.json({ message: "Entry updated", entry: safe });
  } catch (err) {
    console.error("Update entry error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};

exports.deleteEntry = async (req, res) => {
  try {
    const { id } = req.params;
    const entry = await JournalEntry.findById(id);
    if (!entry) return res.status(404).json({ message: "Entry not found" });
    if (String(entry.user) !== String(req.user.id)) {
      return res.status(403).json({ message: "Forbidden" });
    }
    await entry.deleteOne();
    return res.json({ message: "Entry deleted" });
  } catch (err) {
    console.error("Delete entry error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};


exports.summary = async (req, res) => {
  try {
    const userId = req.user.id;
    const since = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    const lastWeekEntries = await JournalEntry.find({
      user: userId,
      createdAt: { $gte: since },
    }).sort({ createdAt: -1 });

    const moodCounts = {
      sadness: 0,
      joy: 0,
      love: 0,
      anger: 0,
      fear: 0,
      surprise: 0,
    };

    lastWeekEntries.forEach((e) => {
      const mood = decryptString(e.mood);
      if (mood && moodCounts[mood] !== undefined) {
        moodCounts[mood] += 1;
      }
    });

    const recentEntriesRaw = await JournalEntry.find({ user: userId })
      .sort({ createdAt: -1 })
      .limit(3);
    const recentEntries = recentEntriesRaw.map((e) => {
      const obj = e.toObject();
      obj.text = decryptString(obj.text) || "[Unable to decrypt - encrypted with different keys]";
      obj.mood = decryptString(obj.mood) || "unknown";
      return obj;
    });

    return res.json({ moodCounts, recentEntries });
  } catch (err) {
    console.error("Summary error:", err);
    return res.status(500).json({ message: "Server error" });
  }
};
