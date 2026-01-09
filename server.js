// ===== REQUIRED PACKAGES =====
const express = require("express");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");

// ===== IMPORT USER MODEL =====
const User = require("./models/User");

// ===== APP SETUP =====
const app = express();
app.use(express.json());

// ===== JWT SECRET =====
const JWT_SECRET = "process.env.JWT_SECRET"; // baad me .env me rakhenge

// ===== MONGODB CONNECTION =====
mongoose.connect("process.env.MONGO_URI")
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.log("❌ MongoDB error:", err));

// ===== ROOT ROUTE =====
app.get("/", (req, res) => {
  res.send("Server is running ✅");
});

// ================= REGISTER API =================
app.post("/register", async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // check user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ message: "User already exists" });
    }

    // hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // save user
    const user = new User({
      name,
      email,
      password: hashedPassword
    });

    await user.save();

    res.json({ message: "User registered successfully" });

  } catch (error) {
    res.status(500).json({ message: "Register error" });
  }
});

// ================= LOGIN API =================
app.post("/login", async (req, res) => {
  try {
    const { email, password } = req.body;

    // check user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // compare password
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }

    // generate JWT token
    const token = jwt.sign(
      { userId: user._id },
      JWT_SECRET,
      { expiresIn: "1h" }
    );

    res.json({
      message: "Login successful",
      token
    });

  } catch (error) {
    console.error(err);
    res.status(500).json({ message: "Register error",error : err.message });
  }
});

// ===== SERVER START =====
const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});
