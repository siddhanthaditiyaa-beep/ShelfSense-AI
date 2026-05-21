/* =========================================
   SHELFSENSE AI — Multi-Agent SaaS Platform
   server.js — Main Backend
   Multi-tenant + Google OAuth + 10 Agents
========================================= */

require("dotenv").config();
const express = require("express");
const mongoose = require("mongoose");
const fetch = require("node-fetch");
const multer = require("multer");
const path = require("path");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mongoSanitize = require("express-mongo-sanitize");
const cors = require("cors");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const cron = require("node-cron");
const axios = require("axios");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");

const { mapSlotsToProducts, updatePlanogram, getPlanogram } = require("./slotProductMapper");

const app = express();

/* =========================
   RAZORPAY
========================= */
const razorpay = new Razorpay({
  key_id: process.env.RAZORPAY_KEY_ID,
  key_secret: process.env.RAZORPAY_KEY_SECRET
});

/* =========================
   EMAIL
========================= */
const emailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.ALERT_EMAIL,
    pass: process.env.ALERT_EMAIL_PASSWORD
  }
});

async function sendAlert(subject, message, isUrgent = false, toEmail = null) {
  try {
    await emailTransporter.sendMail({
      from: `"ShelfSense AI 🤖" <${process.env.ALERT_EMAIL}>`,
      to: toEmail || process.env.ADMIN_ALERT_EMAIL,
      subject: `${isUrgent ? "🚨 URGENT: " : "⚠️ "}${subject}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
          <div style="background:${isUrgent ? '#dc2626' : '#6366f1'};padding:20px;border-radius:10px 10px 0 0">
            <h1 style="color:white;margin:0;font-size:1.4rem">${isUrgent ? '🚨' : '⚠️'} ShelfSense AI Alert</h1>
          </div>
          <div style="background:#f8fafc;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e2e8f0">
            <p style="font-size:1rem;color:#1e293b;line-height:1.6">${message}</p>
            <hr style="border:1px solid #e2e8f0;margin:16px 0">
            <p style="font-size:0.8rem;color:#94a3b8">ShelfSense AI • ${new Date().toLocaleString()}</p>
          </div>
        </div>`
    });
    console.log(`📧 Alert sent: ${subject}`);
  } catch (err) {
    console.error("Email error:", err.message);
  }
}

/* =========================
   SECURITY MIDDLEWARE
========================= */
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: { secure: false, maxAge: 24 * 60 * 60 * 1000 }
}));

app.use(passport.initialize());
app.use(passport.session());

const allowedOrigins = ["http://localhost:3000", "http://127.0.0.1:3000", process.env.FRONTEND_URL].filter(Boolean);
app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

const loginLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 5, message: { message: "Too many login attempts" }, standardHeaders: true, legacyHeaders: false });
const signupLimiter = rateLimit({ windowMs: 60 * 60 * 1000, max: 10, message: { message: "Too many signup attempts" }, standardHeaders: true, legacyHeaders: false });

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(mongoSanitize());

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

/* =========================
   IMAGE UPLOAD
========================= */
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});
const fileFilter = (req, file, cb) => {
  const allowedTypes = ["image/jpeg", "image/jpg", "image/png", "image/webp"];
  if (allowedTypes.includes(file.mimetype)) cb(null, true);
  else cb(new Error("Only images allowed"), false);
};
const upload = multer({ storage, fileFilter, limits: { fileSize: 10 * 1024 * 1024 } });

/* =========================
   MONGODB
========================= */
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ Mongo error", err));

/* =========================
   SCHEMAS
========================= */
const StoreSchema = new mongoose.Schema({
  name: { type: String, required: true },
  ownerName: String,
  ownerEmail: { type: String, unique: true, lowercase: true },
  password: String,
  googleId: String,
  avatar: String,
  plan: { type: String, default: "free", enum: ["free", "pro", "enterprise"] },
  planExpiresAt: Date,
  isActive: { type: Boolean, default: true },
  openingTime: { type: String, default: "09:00" },
  closingTime: { type: String, default: "22:00" },
  alertEmail: String,
  weatherCity: { type: String, default: "Mumbai" },
  address: String,
  phone: String,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  createdAt: { type: Date, default: Date.now }
});

const UserSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  role: { type: String, default: "customer", enum: ["customer", "admin", "superadmin"] },
  fname: String,
  lname: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  googleId: String,
  avatar: String,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  createdAt: { type: Date, default: Date.now }
});

const ItemSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  key: String,
  name: { type: String, maxlength: 100 },
  stock: { type: Number, min: 0, max: 99999 },
  salesHistory: { type: [Number], default: [] },
  avgRating: { type: Number, default: 0 },
  totalRatings: { type: Number, default: 0 },
  price: { type: Number, default: 99 },
  onSale: { type: Boolean, default: false },
  salePercent: { type: Number, default: 0 },
  salePrice: { type: Number, default: 0 },
  expiryDate: { type: Date, default: null },
  category: { type: String, default: "general" },
  supplier: { type: String, default: "" },
  minStockLevel: { type: Number, default: 3 }
});

const OrderSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  userEmail: String,
  cart: Object,
  itemNames: Object,
  totalItems: Number,
  totalAmount: Number,
  paymentId: String,
  paymentStatus: { type: String, default: "pending" },
  time: String,
  createdAt: { type: Date, default: Date.now }
});

const LogSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  type: String,
  agent: { type: String, default: "system" },
  item: String,
  stock: Number,
  message: String,
  severity: { type: String, default: "info", enum: ["info", "warning", "critical"] },
  time: String,
  createdAt: { type: Date, default: Date.now }
});

const ShelfScanSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  shelf_id: String, imagePath: String,
  total_slots: Number, occupied_slots: Number, empty_slots: Number,
  occupied_slot_numbers: Array, empty_slot_numbers: Array,
  present_products: Array, missing_products: Array,
  detection_details: Array, stock_counts: Object,
  fill_percentage: Number, detectedAt: String
});

const FranchiseSchema = new mongoose.Schema({
  name: String, address: String,
  lat: Number, lng: Number, inventory: Object
});

const SecurityLogSchema = new mongoose.Schema({
  type: String, ip: String, path: String, message: String,
  time: { type: Date, default: Date.now }
});

const RatingSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  itemKey: String,
  rating: { type: Number, min: 1, max: 5 },
  createdAt: { type: Date, default: Date.now }
});

const PurchaseOrderSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  itemKey: String, itemName: String,
  quantity: Number, supplier: String,
  status: { type: String, default: "pending", enum: ["pending", "sent", "received"] },
  createdAt: { type: Date, default: Date.now }
});

const AgentLogSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  agent: String, action: String, details: Object,
  severity: { type: String, default: "info" },
  createdAt: { type: Date, default: Date.now }
});

/* =========================
   MODELS
========================= */
const Store = mongoose.model("Store", StoreSchema);
const User = mongoose.model("User", UserSchema);
const Item = mongoose.model("Item", ItemSchema);
const Order = mongoose.model("Order", OrderSchema);
const Log = mongoose.model("Log", LogSchema);
const ShelfScan = mongoose.model("ShelfScan", ShelfScanSchema);
const Franchise = mongoose.model("Franchise", FranchiseSchema);
const SecurityLog = mongoose.model("SecurityLog", SecurityLogSchema);
const Rating = mongoose.model("Rating", RatingSchema);
const PurchaseOrder = mongoose.model("PurchaseOrder", PurchaseOrderSchema);
const AgentLog = mongoose.model("AgentLog", AgentLogSchema);

/* =========================
   HELPERS
========================= */
function validateInput(str, maxLen = 200) {
  if (!str) return false;
  if (str.length > maxLen) return false;
  const dangerous = ["<script", "javascript:", "$where", "DROP TABLE", "eval("];
  return !dangerous.some(p => str.toLowerCase().includes(p.toLowerCase()));
}

function isWithinShopHours(openingTime, closingTime) {
  const now = new Date();
  const current = now.getHours() * 60 + now.getMinutes();
  const [openH, openM] = openingTime.split(":").map(Number);
  const [closeH, closeM] = closingTime.split(":").map(Number);
  return current >= openH * 60 + openM && current <= closeH * 60 + closeM;
}

async function logAgent(storeId, agent, action, details = {}, severity = "info") {
  await AgentLog.create({ storeId, agent, action, details, severity });
  await Log.create({
    storeId, type: "agent", agent,
    item: details.item || agent,
    stock: details.stock || 0,
    message: action, severity,
    time: new Date().toLocaleString()
  });
}

function calculateDistance(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng/2) * Math.sin(dLng/2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

/* =========================
   GOOGLE OAUTH
========================= */
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: "/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    // Check if store already exists with this Google ID
    let store = await Store.findOne({ googleId: profile.id });

    if (!store) {
      // Check if store exists with same email
      store = await Store.findOne({ ownerEmail: profile.emails[0].value });
      if (store) {
        store.googleId = profile.id;
        store.avatar = profile.photos[0]?.value;
        await store.save();
      } else {
        // Create new store
        store = await Store.create({
          name: `${profile.displayName}'s Store`,
          ownerName: profile.displayName,
          ownerEmail: profile.emails[0].value,
          googleId: profile.id,
          avatar: profile.photos[0]?.value,
          plan: "free"
        });

        // Seed default inventory for new store
        await seedStoreInventory(store._id);
      }
    }

    return done(null, store);
  } catch (err) {
    return done(err, null);
  }
}));

passport.serializeUser((store, done) => done(null, store._id));
passport.deserializeUser(async (id, done) => {
  const store = await Store.findById(id);
  done(null, store);
});

/* =========================
   SEED STORE INVENTORY
========================= */
async function seedStoreInventory(storeId) {
  await Item.insertMany([
    { storeId, key: "chocolates", name: "Chocolates", stock: 15, salesHistory: [2,3,2,4,3], price: 149, category: "snacks", supplier: "Nestle", minStockLevel: 3 },
    { storeId, key: "biscuits", name: "Biscuits", stock: 20, salesHistory: [1,2,3,2,1], price: 49, category: "snacks", supplier: "Britannia", minStockLevel: 5 },
    { storeId, key: "chips", name: "Chips", stock: 18, salesHistory: [3,4,3,5,4], price: 29, category: "snacks", supplier: "Lays", minStockLevel: 4 },
    { storeId, key: "juice", name: "Juice", stock: 12, salesHistory: [2,2,3,2,3], price: 99, category: "beverages", supplier: "Tropicana", minStockLevel: 4 },
    { storeId, key: "soft-drinks", name: "Soft Drinks", stock: 25, salesHistory: [4,5,4,6,5], price: 59, category: "beverages", supplier: "Coca-Cola", minStockLevel: 5 },
    { storeId, key: "canned-food", name: "Canned Food", stock: 10, salesHistory: [1,1,2,1,2], price: 199, category: "food", supplier: "Generic", minStockLevel: 3 },
    { storeId, key: "rice", name: "Rice", stock: 15, salesHistory: [2,3,2,3,2], price: 89, category: "staples", supplier: "Local", minStockLevel: 4 },
    { storeId, key: "salt", name: "Salt", stock: 20, salesHistory: [1,1,1,2,1], price: 25, category: "staples", supplier: "Tata", minStockLevel: 5 }
  ]);
  console.log(`✅ Inventory seeded for store ${storeId}`);
}

/* =========================
   INIT — Super Admin + Franchises
========================= */
async function init() {
  // Create super admin
  if (!(await User.findOne({ role: "superadmin" }))) {
    const hashedPassword = await bcrypt.hash("superadmin123", 12);
    await User.create({
      role: "superadmin",
      fname: "Super", lname: "Admin",
      email: "superadmin@shelfsense.ai",
      password: hashedPassword
    });
    console.log("✅ Super admin created — email: superadmin@shelfsense.ai, password: superadmin123");
  }

  // Seed franchises
  if ((await Franchise.countDocuments()) === 0) {
    await Franchise.insertMany([
      { name: "ShelfSense - Andheri West", address: "Andheri West, Mumbai", lat: 19.1360, lng: 72.8296, inventory: { chocolates: 10, biscuits: 5, chips: 8, juice: 3, "soft-drinks": 12 } },
      { name: "ShelfSense - Bandra", address: "Bandra, Mumbai", lat: 19.0596, lng: 72.8295, inventory: { chocolates: 0, biscuits: 15, chips: 0, juice: 8, "soft-drinks": 6 } },
      { name: "ShelfSense - Powai", address: "Powai, Mumbai", lat: 19.1176, lng: 72.9060, inventory: { chocolates: 7, biscuits: 0, chips: 5, juice: 0, "soft-drinks": 9 } },
      { name: "ShelfSense - Thane", address: "Thane, Maharashtra", lat: 19.2183, lng: 72.9781, inventory: { chocolates: 4, biscuits: 8, chips: 6, juice: 5, "soft-drinks": 3 } },
      { name: "ShelfSense - Pune", address: "Pune, Maharashtra", lat: 18.5204, lng: 73.8567, inventory: { chocolates: 9, biscuits: 6, chips: 4, juice: 7, "soft-drinks": 8 } }
    ]);
    console.log("✅ Franchises seeded");
  }
}
init();

/* =========================
   JWT AUTH
========================= */
function auth(role) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token provided" });
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (role && decoded.role !== role && decoded.role !== "superadmin") {
        return res.status(403).json({ message: "Forbidden" });
      }
      req.user = decoded;
      next();
    } catch (err) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };
}

/* =========================
   GOOGLE OAUTH ROUTES
========================= */
app.get("/auth/google",
  passport.authenticate("google", { scope: ["profile", "email"] })
);

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login.html?error=google_failed" }),
  async (req, res) => {
    try {
      const store = req.user;

      // Check if store needs onboarding
      const needsOnboarding = !store.address || store.name.includes("'s Store");

      // Generate JWT
      const token = jwt.sign(
        {
          id: store._id,
          role: "admin",
          email: store.ownerEmail,
          fname: store.ownerName,
          storeId: store._id,
          storeName: store.name,
          plan: store.plan
        },
        process.env.JWT_SECRET,
        { expiresIn: "24h" }
      );

      // Redirect with token
      if (needsOnboarding) {
        res.redirect(`/onboarding.html?token=${token}&new=true`);
      } else {
        res.redirect(`/admin.html?token=${token}`);
      }
    } catch (err) {
      res.redirect("/login.html?error=server_error");
    }
  }
);

/* =========================
   STORE REGISTRATION
========================= */
app.post("/register-store", signupLimiter, async (req, res) => {
  try {
    const { storeName, ownerName, email, password, plan } = req.body;

    if (!storeName || !ownerName || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }

    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }

    if (await Store.findOne({ ownerEmail: email.toLowerCase() })) {
      return res.status(400).json({ message: "An account with this email already exists" });
    }

    const hashedPassword = await bcrypt.hash(password, 12);
    const store = await Store.create({
      name: storeName,
      ownerName,
      ownerEmail: email.toLowerCase(),
      password: hashedPassword,
      plan: plan || "free",
      alertEmail: email.toLowerCase()
    });

    // Seed default inventory
    await seedStoreInventory(store._id);

    // Send welcome email
    await sendAlert(
      "Welcome to ShelfSense AI! 🎉",
      `Hi ${ownerName}!<br><br>
      Your store <strong>${storeName}</strong> has been successfully created on ShelfSense AI.<br><br>
      Your 10 AI agents are now active and monitoring your store 24/7.<br><br>
      <strong>Login:</strong> <a href="http://localhost:3000/login.html">http://localhost:3000/login.html</a><br><br>
      Welcome aboard!`,
      false,
      email
    );

    const token = jwt.sign(
      {
        id: store._id,
        role: "admin",
        email: store.ownerEmail,
        fname: ownerName,
        storeId: store._id,
        storeName: store.name,
        plan: store.plan
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ message: "Store created successfully!", token, storeId: store._id });
  } catch (err) {
    console.error("Register error:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   STORE LOGIN
========================= */
app.post("/login-store", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });

    const store = await Store.findOne({ ownerEmail: email.toLowerCase() });
    if (!store) return res.status(401).json({ message: "Invalid credentials" });

    if (store.lockUntil && store.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((store.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ message: `Account locked. Try again in ${minutesLeft} minutes` });
    }

    const passwordMatch = await bcrypt.compare(password, store.password);
    if (!passwordMatch) {
      store.loginAttempts += 1;
      if (store.loginAttempts >= 5) {
        store.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
        store.loginAttempts = 0;
      }
      await store.save();
      return res.status(401).json({ message: "Invalid credentials" });
    }

    store.loginAttempts = 0;
    store.lockUntil = null;
    await store.save();

    const token = jwt.sign(
      {
        id: store._id,
        role: "admin",
        email: store.ownerEmail,
        fname: store.ownerName,
        storeId: store._id,
        storeName: store.name,
        plan: store.plan
      },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ token, role: "admin", fname: store.ownerName, storeName: store.name, plan: store.plan });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   CUSTOMER AUTH (unchanged)
========================= */
app.post("/signup", signupLimiter, async (req, res) => {
  try {
    const { fname, lname, email, password } = req.body;
    if (!fname || !lname || !email || !password) return res.status(400).json({ message: "All fields required" });
    if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (await User.findOne({ email: email.toLowerCase() })) return res.status(400).json({ message: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ fname, lname, email: email.toLowerCase(), password: hashedPassword });
    res.json({ message: "Account created successfully" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Username and password required" });
    const user = await User.findOne({ email: username.toLowerCase() });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ message: `Account locked. Try again in ${minutesLeft} minutes` });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) { user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); user.loginAttempts = 0; }
      await user.save();
      return res.status(401).json({ message: "Invalid credentials" });
    }
    user.loginAttempts = 0; user.lockUntil = null; await user.save();
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email, fname: user.fname },
      process.env.JWT_SECRET, { expiresIn: "24h" }
    );
    res.json({ token, role: user.role, fname: user.fname });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/logout", (req, res) => {
  req.logout(() => {});
  res.json({ message: "Logged out successfully" });
});

/* =========================
   ONBOARDING
========================= */
app.post("/complete-onboarding", auth("admin"), async (req, res) => {
  try {
    const { storeName, address, phone, openingTime, closingTime, weatherCity } = req.body;
    await Store.updateOne(
      { _id: req.user.storeId },
      { $set: { name: storeName, address, phone, openingTime, closingTime, weatherCity } }
    );
    res.json({ message: "Store setup complete!" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   SHOP ITEMS (store-specific)
========================= */
app.get("/shop-items", auth("customer"), async (req, res) => {
  try {
    // Get storeId from query or use first store
    const storeId = req.query.storeId;
    const query = storeId ? { storeId } : {};
    const items = await Item.find(query);
    const view = {};
    items.forEach(i => {
      view[i.key] = {
        name: i.name, stock: i.stock, price: i.price || 99,
        onSale: i.onSale || false, salePercent: i.salePercent || 0,
        salePrice: i.salePrice || i.price || 99,
        canBuy: i.stock > 0, warning: i.stock <= 3 ? i.stock : null,
        avgRating: i.avgRating || 0, totalRatings: i.totalRatings || 0
      };
    });
    res.json(view);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   CHECKOUT
========================= */
app.post("/checkout", auth("customer"), async (req, res) => {
  try {
    const { cart, storeId } = req.body;
    if (!cart || typeof cart !== "object") return res.status(400).json({ message: "Invalid cart" });
    const adjusted = {}, itemNames = {}, notices = [];
    let totalItems = 0, totalAmount = 0;
    for (const key in cart) {
      if (!validateInput(key, 50)) continue;
      const item = await Item.findOne({ key, storeId: storeId || { $exists: true } });
      if (!item) continue;
      const qty = Math.max(0, Math.min(parseInt(cart[key]) || 0, 100));
      const allowed = Math.min(qty, item.stock);
      adjusted[key] = allowed; itemNames[key] = item.name;
      totalItems += allowed;
      totalAmount += (item.onSale ? item.salePrice : item.price || 99) * allowed;
      if (qty > item.stock) notices.push(`${item.name}: only ${item.stock} available`);
      await Item.updateOne({ key, storeId: item.storeId }, {
        $inc: { stock: -allowed },
        $push: { salesHistory: { $each: [allowed], $slice: -30 } }
      });
    }
    await Order.create({
      storeId, userId: req.user.id, userEmail: req.user.email,
      cart: adjusted, itemNames, totalItems, totalAmount,
      paymentStatus: "paid", time: new Date().toLocaleString()
    });
    res.json({ message: "Order placed successfully", notices });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   RAZORPAY
========================= */
app.post("/create-payment-order", auth("customer"), async (req, res) => {
  try {
    const { cart, storeId } = req.body;
    if (!cart) return res.status(400).json({ message: "Invalid cart" });
    let totalAmount = 0;
    for (const key in cart) {
      const item = await Item.findOne({ key, storeId: storeId || { $exists: true } });
      if (item && cart[key] > 0) totalAmount += (item.onSale ? item.salePrice : item.price || 99) * cart[key];
    }
    if (totalAmount === 0) return res.status(400).json({ message: "Cart is empty" });
    const order = await razorpay.orders.create({
      amount: totalAmount * 100, currency: "INR",
      receipt: `order_${Date.now()}`,
      notes: { userId: req.user.id, userEmail: req.user.email }
    });
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    console.error("Payment error:", err.message);
    res.status(500).json({ message: "Failed to create payment order" });
  }
});

app.post("/verify-payment", auth("customer"), async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, cart, storeId } = req.body;
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(body).digest("hex");
    if (expectedSignature !== razorpay_signature) return res.status(400).json({ message: "Payment verification failed" });
    const adjusted = {}, itemNames = {}, notices = [];
    let totalItems = 0, totalAmount = 0;
    for (const key in cart) {
      if (!validateInput(key, 50)) continue;
      const item = await Item.findOne({ key, storeId: storeId || { $exists: true } });
      if (!item) continue;
      const qty = Math.max(0, Math.min(parseInt(cart[key]) || 0, 100));
      const allowed = Math.min(qty, item.stock);
      adjusted[key] = allowed; itemNames[key] = item.name;
      totalItems += allowed;
      totalAmount += (item.onSale ? item.salePrice : item.price || 99) * allowed;
      if (qty > item.stock) notices.push(`${item.name}: only ${item.stock} available`);
      await Item.updateOne({ key, storeId: item.storeId }, {
        $inc: { stock: -allowed },
        $push: { salesHistory: { $each: [allowed], $slice: -30 } }
      });
    }
    await Order.create({
      storeId, userId: req.user.id, userEmail: req.user.email,
      cart: adjusted, itemNames, totalItems, totalAmount,
      paymentId: razorpay_payment_id, paymentStatus: "paid",
      time: new Date().toLocaleString()
    });
    res.json({ message: "Payment successful!", paymentId: razorpay_payment_id, notices });
  } catch (err) { res.status(500).json({ message: "Payment verification error" }); }
});

/* =========================
   ORDER HISTORY
========================= */
app.get("/my-orders", auth("customer"), async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(20);
    res.json(orders);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   RATINGS
========================= */
app.post("/rate-product", auth("customer"), async (req, res) => {
  try {
    const { itemKey, rating, storeId } = req.body;
    if (!itemKey || !rating || rating < 1 || rating > 5) return res.status(400).json({ message: "Invalid rating" });
    const item = await Item.findOne({ key: itemKey, storeId: storeId || { $exists: true } });
    if (!item) return res.status(404).json({ message: "Item not found" });
    const existing = await Rating.findOne({ userId: req.user.id, itemKey, storeId: item.storeId });
    if (existing) { existing.rating = rating; await existing.save(); }
    else await Rating.create({ storeId: item.storeId, userId: req.user.id, itemKey, rating });
    const allRatings = await Rating.find({ itemKey, storeId: item.storeId });
    const avg = allRatings.reduce((a, b) => a + b.rating, 0) / allRatings.length;
    await Item.updateOne({ key: itemKey, storeId: item.storeId }, {
      $set: { avgRating: Math.round(avg * 10) / 10, totalRatings: allRatings.length }
    });
    res.json({ message: "Rating saved!", avgRating: Math.round(avg * 10) / 10, totalRatings: allRatings.length });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/my-ratings", auth("customer"), async (req, res) => {
  try {
    const ratings = await Rating.find({ userId: req.user.id });
    const ratingMap = {};
    ratings.forEach(r => { ratingMap[r.itemKey] = r.rating; });
    res.json(ratingMap);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   ADMIN ROUTES (store-specific)
========================= */
app.get("/admin-data", auth("admin"), async (req, res) => {
  try {
    const storeId = req.user.storeId;
    const inventory = await Item.find({ storeId });
    const monitoring = await Log.find({ storeId, type: "agent" }).sort({ _id: -1 }).limit(50);
    const forecasting = await Log.find({ storeId, agent: "Forecasting Agent" }).sort({ _id: -1 }).limit(20);
    res.json({ inventory, monitoring, forecasting });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/add-item", auth("admin"), async (req, res) => {
  try {
    const { name, stock } = req.body;
    const storeId = req.user.storeId;
    if (!name || !validateInput(name, 100)) return res.status(400).json({ message: "Invalid item name" });
    const stockNum = parseInt(stock);
    if (isNaN(stockNum) || stockNum < 0) return res.status(400).json({ message: "Invalid stock" });
    const key = name.toLowerCase().replace(/\s+/g, "-");
    if (await Item.findOne({ key, storeId })) return res.status(400).json({ message: "Item already exists" });
    await Item.create({ storeId, key, name, stock: stockNum, salesHistory: [] });
    res.json({ message: "Item added!" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/update-stock", auth("admin"), async (req, res) => {
  try {
    const { key, stock } = req.body;
    const storeId = req.user.storeId;
    const stockNum = parseInt(stock);
    if (isNaN(stockNum) || stockNum < 0) return res.status(400).json({ message: "Invalid stock" });
    await Item.updateOne({ key, storeId }, { $set: { stock: stockNum } });
    res.json({ message: `Stock updated to ${stockNum}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/update-price", auth("admin"), async (req, res) => {
  try {
    const { key, price } = req.body;
    const storeId = req.user.storeId;
    const priceNum = parseFloat(price);
    if (isNaN(priceNum) || priceNum < 0) return res.status(400).json({ message: "Invalid price" });
    await Item.updateOne({ key, storeId }, { $set: { price: priceNum } });
    res.json({ message: `Price updated to ₹${priceNum}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/update-sale", auth("admin"), async (req, res) => {
  try {
    const { key, onSale, salePercent } = req.body;
    const storeId = req.user.storeId;
    const item = await Item.findOne({ key, storeId });
    if (!item) return res.status(404).json({ message: "Item not found" });
    const pct = parseFloat(salePercent) || 0;
    const salePrice = onSale ? Math.round(item.price * (1 - pct / 100)) : item.price;
    await Item.updateOne({ key, storeId }, { $set: { onSale, salePercent: pct, salePrice } });
    res.json({ message: onSale ? `Sale set: ${pct}% off` : "Sale removed" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.delete("/admin/delete-item/:key", auth("admin"), async (req, res) => {
  try {
    await Item.deleteOne({ key: req.params.key, storeId: req.user.storeId });
    res.json({ message: "Item deleted" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/reset-logs", auth("admin"), async (req, res) => {
  try {
    const storeId = req.user.storeId;
    await Log.deleteMany({ storeId });
    await AgentLog.deleteMany({ storeId });
    const defaults = { chocolates: 15, biscuits: 20, chips: 18, juice: 12, "soft-drinks": 25, "canned-food": 10, rice: 15, salt: 20 };
    for (const key in defaults) {
      await Item.updateOne({ key, storeId }, { $set: { stock: defaults[key], salesHistory: [] } });
    }
    res.json({ message: "Reset successful" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/agent-logs", auth("admin"), async (req, res) => {
  try {
    const storeId = req.user.storeId;
    const { agent, severity } = req.query;
    const filter = { storeId };
    if (agent && agent !== "all") filter.agent = agent;
    if (severity && severity !== "all") filter.severity = severity;
    const logs = await AgentLog.find(filter).sort({ createdAt: -1 }).limit(100);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/purchase-orders", auth("admin"), async (req, res) => {
  try {
    const orders = await PurchaseOrder.find({ storeId: req.user.storeId }).sort({ createdAt: -1 }).limit(20);
    res.json(orders);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/purchase-orders/:id/status", auth("admin"), async (req, res) => {
  try {
    const { status } = req.body;
    await PurchaseOrder.updateOne({ _id: req.params.id }, { $set: { status } });
    if (status === "received") {
      const order = await PurchaseOrder.findById(req.params.id);
      if (order) await Item.updateOne({ key: order.itemKey, storeId: req.user.storeId }, { $inc: { stock: order.quantity } });
    }
    res.json({ message: `Order ${status}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/settings", auth("admin"), async (req, res) => {
  try {
    const store = await Store.findById(req.user.storeId);
    res.json(store);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/settings", auth("admin"), async (req, res) => {
  try {
    const { openingTime, closingTime, storeName, alertEmail, weatherCity, address, phone } = req.body;
    await Store.updateOne({ _id: req.user.storeId }, {
      $set: { openingTime, closingTime, name: storeName, alertEmail, weatherCity, address, phone }
    });
    res.json({ message: "Settings saved!" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/shelf-scans", auth("admin"), async (req, res) => {
  try {
    const scans = await ShelfScan.find({ storeId: req.user.storeId }).sort({ _id: -1 }).limit(10);
    res.json(scans);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/franchises", auth("admin"), async (req, res) => {
  try {
    const franchises = await Franchise.find();
    res.json(franchises);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/planogram", auth("admin"), (req, res) => {
  try { res.json(getPlanogram()); }
  catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/planogram", auth("admin"), (req, res) => {
  try {
    const { shelfId, slotMapping } = req.body;
    if (!shelfId || !slotMapping) return res.status(400).json({ message: "shelfId and slotMapping required" });
    updatePlanogram(shelfId, slotMapping);
    res.json({ message: `Planogram updated for ${shelfId}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/scan-shelf", auth("admin"), upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No image uploaded" });
    const imagePath = `/uploads/${req.file.filename}`;
    const totalSlots = parseInt(req.body.total_slots) || 8;
    const shelfId = req.body.shelf_id || "SHELF_001";
    const storeId = req.user.storeId;

    const mlResponse = await fetch("http://127.0.0.1:5001/process-shelf-image", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ imagePath, total_slots: totalSlots, shelf_id: shelfId })
    });

    if (!mlResponse.ok) throw new Error("ML service error");
    const mlData = await mlResponse.json();

    let presentProducts = mlData.present_products || [];
    let missingProducts = mlData.missing_products || [];

    try {
      const mapped = mapSlotsToProducts(shelfId, mlData.occupied_slot_numbers, mlData.empty_slot_numbers);
      presentProducts = mapped.present_products;
      missingProducts = mapped.missing_products;
    } catch (mapErr) { console.log("Planogram note:", mapErr.message); }

    await ShelfScan.create({
      storeId, shelf_id: shelfId, imagePath,
      total_slots: mlData.total_slots, occupied_slots: mlData.occupied_slots,
      empty_slots: mlData.empty_slots, occupied_slot_numbers: mlData.occupied_slot_numbers,
      empty_slot_numbers: mlData.empty_slot_numbers, present_products: presentProducts,
      missing_products: missingProducts, detection_details: mlData.detection_details || [],
      stock_counts: mlData.stock_counts || {}, fill_percentage: mlData.fill_percentage || 0,
      detectedAt: new Date().toLocaleString()
    });

    res.json({
      message: "Shelf scanned!", imagePath, shelf_id: shelfId,
      total_slots: mlData.total_slots, occupied_slots: mlData.occupied_slots,
      empty_slots: mlData.empty_slots, occupied_slot_numbers: mlData.occupied_slot_numbers,
      empty_slot_numbers: mlData.empty_slot_numbers, present_products: presentProducts,
      missing_products: missingProducts, detection_details: mlData.detection_details,
      stock_counts: mlData.stock_counts, fill_percentage: mlData.fill_percentage,
      low_stock_alert: mlData.low_stock_alert, total_detections: mlData.total_detections
    });
  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   NEARBY FRANCHISES
========================= */
app.get("/nearby-franchises", auth("customer"), async (req, res) => {
  try {
    const { product, lat, lng } = req.query;
    if (!product || !lat || !lng) return res.status(400).json({ message: "product, lat, lng required" });
    const franchises = await Franchise.find();
    const results = franchises
      .filter(f => f.inventory[product] && f.inventory[product] > 0)
      .map(f => ({
        name: f.name, address: f.address, stock: f.inventory[product],
        distance: calculateDistance(parseFloat(lat), parseFloat(lng), f.lat, f.lng).toFixed(2),
        lat: f.lat, lng: f.lng
      }))
      .sort((a, b) => a.distance - b.distance);
    res.json(results);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   SUPER ADMIN ROUTES
========================= */
app.get("/superadmin/stores", auth("superadmin"), async (req, res) => {
  try {
    const stores = await Store.find().select("-password").sort({ createdAt: -1 });
    res.json(stores);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/superadmin/stats", auth("superadmin"), async (req, res) => {
  try {
    const totalStores = await Store.countDocuments();
    const totalOrders = await Order.countDocuments();
    const totalItems = await Item.countDocuments();
    const planCounts = await Store.aggregate([
      { $group: { _id: "$plan", count: { $sum: 1 } } }
    ]);
    res.json({ totalStores, totalOrders, totalItems, planCounts });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/superadmin/update-plan", auth("superadmin"), async (req, res) => {
  try {
    const { storeId, plan } = req.body;
    await Store.updateOne({ _id: storeId }, { $set: { plan } });
    res.json({ message: `Plan updated to ${plan}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================================
   10 AI AGENTS (store-aware)
========================================= */

/* AGENT 1 — MONITORING */
cron.schedule("*/30 * * * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        if (item.stock === 0) {
          await logAgent(store._id, "Monitoring Agent", `🚨 OUT OF STOCK: ${item.name}`, { item: item.name, stock: 0 }, "critical");
          await sendAlert(`OUT OF STOCK: ${item.name}`, `<strong>${item.name}</strong> is out of stock at <strong>${store.name}</strong>!`, true, store.alertEmail);
        } else if (item.stock <= item.minStockLevel) {
          await logAgent(store._id, "Monitoring Agent", `⚠️ Low stock: ${item.name} has only ${item.stock} units left`, { item: item.name, stock: item.stock }, "warning");
        }
      }
    }
  } catch (err) { console.error("Monitoring Agent error:", err.message); }
});

/* AGENT 2 — FORECASTING */
cron.schedule("0 */15 * * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        const history = item.salesHistory || [];
        if (history.length < 3) continue;
        const alpha = 0.3;
        let smoothed = history[0];
        for (let i = 1; i < history.length; i++) smoothed = alpha * history[i] + (1 - alpha) * smoothed;
        const isWeekend = [0, 6].includes(new Date().getDay());
        const projectedDailySales = smoothed * (isWeekend ? 1.3 : 1.0);
        const daysUntilEmpty = projectedDailySales > 0 ? Math.floor(item.stock / projectedDailySales) : 999;
        if (daysUntilEmpty <= 3 && item.stock > 0) {
          const reorderQty = Math.ceil(projectedDailySales * 7);
          await Item.updateOne({ _id: item._id }, { $inc: { stock: reorderQty } });
          await logAgent(store._id, "Forecasting Agent", `🤖 Auto-reordered ${reorderQty} units of ${item.name} (${daysUntilEmpty} days until empty)`, { item: item.name, stock: reorderQty }, "info");
        }
      }
    }
  } catch (err) { console.error("Forecasting Agent error:", err.message); }
});

/* AGENT 3 — ANOMALY DETECTION */
cron.schedule("*/45 * * * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const withinHours = isWithinShopHours(store.openingTime || "09:00", store.closingTime || "22:00");
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        const history = item.salesHistory || [];
        if (history.length < 5) continue;
        const mean = history.reduce((a, b) => a + b, 0) / history.length;
        const variance = history.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / history.length;
        const std = Math.sqrt(variance);
        const recentDrop = history[history.length - 1];
        const zScore = std > 0 ? (recentDrop - mean) / std : 0;
        if (zScore > 2.5) {
          if (!withinHours) {
            await logAgent(store._id, "Anomaly Detection Agent", `🚨 POSSIBLE THEFT: ${item.name} — Unusual stock drop outside shop hours (${store.openingTime}-${store.closingTime})`, { item: item.name, stock: recentDrop, zScore: zScore.toFixed(2) }, "critical");
            await sendAlert(`POSSIBLE THEFT: ${item.name}`, `🚨 Unusual stock drop of <strong>${recentDrop} units</strong> of <strong>${item.name}</strong> detected outside shop hours at <strong>${store.name}</strong>!<br><br>Check security cameras immediately!`, true, store.alertEmail);
          } else {
            await logAgent(store._id, "Anomaly Detection Agent", `⚠️ Unusual sales spike: ${item.name} (z-score: ${zScore.toFixed(2)})`, { item: item.name, stock: recentDrop, zScore: zScore.toFixed(2) }, "warning");
          }
        }
      }
    }
  } catch (err) { console.error("Anomaly Detection error:", err.message); }
});

/* AGENT 4 — DYNAMIC PRICING */
cron.schedule("0 0 * * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        const history = item.salesHistory || [];
        if (history.length < 3) continue;
        const avgSales = history.slice(-5).reduce((a, b) => a + b, 0) / Math.min(history.length, 5);
        let newPrice = item.price;
        let reason = "";
        if (avgSales > 3 && item.stock <= item.minStockLevel * 2) { newPrice = Math.round(item.price * 1.1); reason = "High demand + low stock"; }
        else if (avgSales < 1 && item.stock > 20) { newPrice = Math.round(item.price * 0.9); reason = "Low demand + excess stock"; }
        if (newPrice !== item.price) {
          await Item.updateOne({ _id: item._id }, { $set: { price: newPrice } });
          await logAgent(store._id, "Dynamic Pricing Agent", `💰 ${item.name}: ₹${item.price} → ₹${newPrice} (${reason})`, { item: item.name, oldPrice: item.price, newPrice, reason }, "info");
        }
      }
    }
  } catch (err) { console.error("Dynamic Pricing error:", err.message); }
});

/* AGENT 5 — COMPETITOR ANALYSIS */
const MARKET_PRICES = { "chocolates": 159, "biscuits": 55, "chips": 35, "juice": 110, "soft-drinks": 65, "canned-food": 210, "rice": 95, "salt": 28 };
cron.schedule("0 0 9 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        const marketPrice = MARKET_PRICES[item.key];
        if (!marketPrice) continue;
        const priceDiff = ((item.price - marketPrice) / marketPrice) * 100;
        if (Math.abs(priceDiff) > 15) {
          await logAgent(store._id, "Competitor Analysis Agent", `🏆 ${item.name}: Your price ₹${item.price} is ${priceDiff.toFixed(1)}% ${priceDiff > 0 ? 'above' : 'below'} market (₹${marketPrice})`, { item: item.name, ourPrice: item.price, marketPrice }, priceDiff > 0 ? "warning" : "info");
        }
      }
    }
  } catch (err) { console.error("Competitor Analysis error:", err.message); }
});

/* AGENT 6 — SUPPLIER */
cron.schedule("0 0 */2 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        if (item.stock <= item.minStockLevel) {
          const existing = await PurchaseOrder.findOne({ storeId: store._id, itemKey: item.key, status: "pending" });
          if (!existing) {
            const orderQty = item.minStockLevel * 5;
            await PurchaseOrder.create({ storeId: store._id, itemKey: item.key, itemName: item.name, quantity: orderQty, supplier: item.supplier || "Default Supplier" });
            await logAgent(store._id, "Supplier Agent", `🔄 Purchase order: ${orderQty} units of ${item.name} from ${item.supplier || "Default Supplier"}`, { item: item.name, quantity: orderQty }, "info");
            await sendAlert(`Purchase Order: ${item.name}`, `Auto-generated order for <strong>${orderQty} units of ${item.name}</strong> at <strong>${store.name}</strong>.`, false, store.alertEmail);
          }
        }
      }
    }
  } catch (err) { console.error("Supplier Agent error:", err.message); }
});

/* AGENT 7 — CUSTOMER BEHAVIOR */
cron.schedule("0 0 1 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const orders = await Order.find({ storeId: store._id }).limit(100);
      if (orders.length < 5) continue;
      const coOccurrence = {};
      for (const order of orders) {
        const items = Object.keys(order.cart || {});
        for (let i = 0; i < items.length; i++) {
          for (let j = i + 1; j < items.length; j++) {
            const pair = [items[i], items[j]].sort().join("+");
            coOccurrence[pair] = (coOccurrence[pair] || 0) + 1;
          }
        }
      }
      const topPairs = Object.entries(coOccurrence).filter(([, c]) => c >= 2).sort((a, b) => b[1] - a[1]).slice(0, 3);
      if (topPairs.length > 0) {
        const insights = topPairs.map(([pair, count]) => `${pair.replace("+", " + ")} (${count}x)`).join(", ");
        await logAgent(store._id, "Customer Behavior Agent", `👥 Bundle opportunities: ${insights}`, { associations: topPairs }, "info");
      }
    }
  } catch (err) { console.error("Customer Behavior error:", err.message); }
});

/* AGENT 8 — WEATHER */
cron.schedule("0 0 8 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const city = store.weatherCity || "Mumbai";
      const geoRes = await axios.get(`https://geocoding-api.open-meteo.com/v1/search?name=${city}&count=1`);
      if (!geoRes.data.results?.length) continue;
      const { latitude, longitude } = geoRes.data.results[0];
      const weatherRes = await axios.get(`https://api.open-meteo.com/v1/forecast?latitude=${latitude}&longitude=${longitude}&current=temperature_2m,weathercode&timezone=auto`);
      const temp = weatherRes.data.current.temperature_2m;
      const code = weatherRes.data.current.weathercode;
      let recommendation = "";
      if (temp > 35) recommendation = "Extremely hot! Stock up on cold drinks and juice.";
      else if (temp > 28) recommendation = "Hot weather — increase beverage stock.";
      else if (code >= 61 && code <= 67) recommendation = "Rainy — stock up on snacks and hot beverages.";
      else if (temp < 20) recommendation = "Cool weather — chocolates will sell well.";
      if (recommendation) await logAgent(store._id, "Weather Agent", `🌦️ ${city}: ${temp}°C — ${recommendation}`, { city, temperature: temp }, "info");
    }
  } catch (err) { console.error("Weather Agent error:", err.message); }
});

/* AGENT 9 — EXPIRY */
cron.schedule("0 0 7 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id, expiryDate: { $ne: null } });
      for (const item of items) {
        if (!item.expiryDate) continue;
        const daysUntilExpiry = Math.ceil((new Date(item.expiryDate) - new Date()) / (1000 * 60 * 60 * 24));
        if (daysUntilExpiry <= 0) {
          await logAgent(store._id, "Expiry Agent", `🗓️ EXPIRED: ${item.name} — Remove from shelves!`, { item: item.name }, "critical");
          await sendAlert(`EXPIRED: ${item.name}`, `<strong>${item.name}</strong> has expired at <strong>${store.name}</strong>. Remove immediately!`, true, store.alertEmail);
        } else if (daysUntilExpiry <= 7) {
          const discountPrice = Math.round(item.price * 0.7);
          await Item.updateOne({ _id: item._id }, { $set: { onSale: true, salePercent: 30, salePrice: discountPrice } });
          await logAgent(store._id, "Expiry Agent", `🗓️ Near-expiry: ${item.name} expires in ${daysUntilExpiry} days — 30% discount applied`, { item: item.name, daysUntilExpiry }, "warning");
        }
      }
    }
  } catch (err) { console.error("Expiry Agent error:", err.message); }
});

/* AGENT 10 — ROUTE OPTIMIZATION */
cron.schedule("0 0 6 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    const franchises = await Franchise.find();
    for (const store of stores) {
      const outOfStock = await Item.find({ storeId: store._id, stock: 0 });
      for (const item of outOfStock) {
        const sources = franchises
          .filter(f => f.inventory[item.key] && f.inventory[item.key] > 5)
          .map(f => ({ name: f.name, address: f.address, stock: f.inventory[item.key], distance: calculateDistance(19.0760, 72.8777, f.lat, f.lng) }))
          .sort((a, b) => a.distance - b.distance);
        if (sources.length > 0) {
          await logAgent(store._id, "Route Optimization Agent", `🗺️ Get ${item.name} from ${sources[0].name} (${sources[0].distance.toFixed(1)} km, ${sources[0].stock} units available)`, { item: item.name, source: sources[0].name }, "info");
        }
      }
    }
  } catch (err) { console.error("Route Optimization error:", err.message); }
});

/* =========================
   ERROR HANDLERS
========================= */
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  res.status(err.status || 500).json({ message: err.message || "Internal server error" });
});

app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 ShelfSense AI running at http://localhost:${PORT}`);
  console.log(`🔒 Security layer active`);
  console.log(`🤖 All 10 AI Agents initialized`);
  console.log(`💳 Razorpay active`);
  console.log(`📧 Email alerts active`);
  console.log(`🔐 Google OAuth active`);
  console.log(`🏪 Multi-tenant SaaS ready`);
});