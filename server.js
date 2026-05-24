/* =========================================
   SHELFSENSE AI — Multi-Agent SaaS Platform
   server.js — Main Backend
   Multi-tenant + Google OAuth + 15 Agents + Full Security
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
const xss = require("xss-clean");
const hpp = require("hpp");
const cors = require("cors");
const cookieParser = require("cookie-parser");
const Razorpay = require("razorpay");
const crypto = require("crypto");
const nodemailer = require("nodemailer");
const cron = require("node-cron");
const axios = require("axios");
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;
const session = require("express-session");
const MongoStore = require("connect-mongo")(session);

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
   JWT BLACKLIST (in-memory)
========================= */
const tokenBlacklist = new Set();

/* =========================
   2FA OTP STORE
========================= */
const otpStore = new Map();

function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}

async function sendOTPEmail(email, otp, name) {
  await emailTransporter.sendMail({
    from: `"ShelfSense AI 🔐" <${process.env.ALERT_EMAIL}>`,
    to: email,
    subject: "Your ShelfSense AI Login OTP",
    html: `
      <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
        <div style="background:#6366f1;padding:20px;border-radius:10px 10px 0 0">
          <h1 style="color:white;margin:0;font-size:1.2rem">🔐 ShelfSense AI — Login Verification</h1>
        </div>
        <div style="background:#f8fafc;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e2e8f0">
          <p style="color:#1e293b">Hi <strong>${name}</strong>,</p>
          <p style="color:#1e293b;margin-top:8px">Your one-time password (OTP) for login is:</p>
          <div style="text-align:center;margin:24px 0">
            <span style="font-size:2.5rem;font-weight:800;letter-spacing:12px;color:#6366f1">${otp}</span>
          </div>
          <p style="color:#64748b;font-size:0.85rem">Expires in <strong>5 minutes</strong>. Do not share it with anyone.</p>
        </div>
      </div>`
  });
}

function blacklistToken(token) {
  tokenBlacklist.add(token);
  // Auto-clean blacklist every hour to prevent memory leak
}
setInterval(() => {
  tokenBlacklist.clear();
  console.log("🧹 JWT blacklist cleared");
}, 60 * 60 * 1000);

/* =========================
   SECURITY MIDDLEWARE
========================= */
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

app.use(session({
  secret: process.env.SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  store: new MongoStore({
    mongooseConnection: mongoose.connection,
    ttl: 24 * 60 * 60
  }),
  cookie: {
    secure: process.env.NODE_ENV === "production",
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000,
    sameSite: "strict"
  }
}));

app.use(passport.initialize());
app.use(passport.session());

const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  "https://shelfsense-ai-lptz.onrender.com",
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization", "X-CSRF-Token"],
  credentials: true
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 20,
  message: { message: "Too many login attempts. Try again in 15 minutes." },
  standardHeaders: true, legacyHeaders: false,
  handler: async (req, res, next, options) => {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    await SecurityLog.create({
      type: "RATE_LIMIT_HIT", ip,
      path: req.path,
      message: `Rate limit exceeded on ${req.path} from IP ${ip}`
    }).catch(() => {});
    res.status(429).json(options.message);
  }
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 10,
  message: { message: "Too many signup attempts" },
  standardHeaders: true, legacyHeaders: false
});

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(cookieParser());
app.use(mongoSanitize());
app.use(xss());
app.use(hpp());

/* =========================
   CSRF TOKEN MIDDLEWARE
========================= */
function generateCsrfToken() {
  return crypto.randomBytes(32).toString("hex");
}

app.get("/csrf-token", (req, res) => {
  const token = generateCsrfToken();
  res.cookie("csrfToken", token, {
    httpOnly: false,
    secure: process.env.NODE_ENV === "production",
    sameSite: "strict",
    maxAge: 60 * 60 * 1000
  });
  res.json({ csrfToken: token });
});

function verifyCsrf(req, res, next) {
  // Skip CSRF for GET requests and OAuth
  if (req.method === "GET" || req.path.startsWith("/auth/")) return next();
  const cookieToken = req.cookies?.csrfToken;
  const headerToken = req.headers["x-csrf-token"];
  if (!cookieToken || !headerToken || cookieToken !== headerToken) {
    return res.status(403).json({ message: "Invalid CSRF token" });
  }
  next();
}

/* =========================
   SUSPICIOUS IP DETECTION
========================= */
const suspiciousIPs = new Map();

function trackSuspiciousIP(req) {
  const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
  const count = (suspiciousIPs.get(ip) || 0) + 1;
  suspiciousIPs.set(ip, count);
  if (count >= 10) {
    SecurityLog.create({
      type: "SUSPICIOUS_IP", ip,
      path: req.path,
      message: `IP ${ip} has ${count} failed attempts`
    }).catch(() => {});
    console.warn(`🚨 Suspicious IP detected: ${ip} with ${count} failures`);
  }
}

// Clean suspicious IPs every hour
setInterval(() => { suspiciousIPs.clear(); }, 60 * 60 * 1000);

app.use((req, res, next) => {
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path}`);
  next();
});

/* =========================
   STATIC FILES
========================= */
app.use(express.static(path.join(__dirname, "public")));
app.use("/uploads", express.static(path.join(__dirname, "uploads")));

/* =========================
   ROOT REDIRECT
========================= */
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "landing.html"));
});

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
  resetToken: String,
  resetTokenExpiry: Date,
twoFactorEnabled: { type: Boolean, default: false },
createdAt: { type: Date, default: Date.now }
});

const UserSchema

const UserSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  role: { type: String, default: "customer", enum: ["customer", "admin", "superadmin"] },
  fname: String,
  lname: String,
  email: { type: String, unique: true, lowercase: true },
  password: String,
  googleId: String,
  avatar: String,
  wishlist: { type: [String], default: [] },
  loginAttempts: { type: Number, default: 0 },
  lockUntil: Date,
  resetToken: String,
  resetTokenExpiry: Date,
twoFactorEnabled: { type: Boolean, default: false },
createdAt: { type: Date, default: Date.now }
});

const ItemSchema

const ItemSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  key: String,
  name: { type: String, maxlength: 100 },
  stock: { type: Number, min: 0, max: 99999 },
  previousStock: { type: Number, default: 0 },
  viewCount: { type: Number, default: 0 },
  cartCount: { type: Number, default: 0 },
  salesHistory: { type: [Number], default: [] },
  avgRating: { type: Number, default: 0 },
  totalRatings: { type: Number, default: 0 },
  sentimentScore: { type: Number, default: 0 },
  price: { type: Number, default: 99 },
  onSale: { type: Boolean, default: false },
  salePercent: { type: Number, default: 0 },
  salePrice: { type: Number, default: 0 },
  autoDiscountApplied: { type: Boolean, default: false },
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
  flaggedAsFraud: { type: Boolean, default: false },
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
  review: { type: String, default: "" },
  createdAt: { type: Date, default: Date.now }
});

const PurchaseOrderSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  itemKey: String, itemName: String,
  quantity: Number, supplier: String,
  status: { type: String, default: "pending", enum: ["pending", "sent", "received"] },
  createdAt: { type: Date, default: Date.now }
});

const SystemSettingsSchema = new mongoose.Schema({
  key: { type: String, unique: true },
  value: { type: String }
});

const AgentLogSchema = new mongoose.Schema({
  storeId: { type: mongoose.Schema.Types.ObjectId, ref: "Store" },
  agent: String, action: String, details: Object,
  severity: { type: String, default: "info" },
  createdAt: { type: Date, default: Date.now }
});

/* NEW: Audit Log Schema */
const AuditLogSchema = new mongoose.Schema({
  userEmail: String,
  role: String,
  action: String,
  ip: String,
  userAgent: String,
  status: { type: String, default: "success" },
  details: String,
  createdAt: { type: Date, default: Date.now }
});

/* NEW: Fraud Log Schema */
const FraudLogSchema = new mongoose.Schema({
  userId: String,
  userEmail: String,
  reason: String,
  orderId: String,
  amount: Number,
  ip: String,
  createdAt: { type: Date, default: Date.now }
});

/* NEW: Wishlist Notification Schema */
const WishlistNotificationSchema = new mongoose.Schema({
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  userEmail: String,
  itemKey: String,
  itemName: String,
  notified: { type: Boolean, default: false },
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
const SystemSettings = mongoose.model("SystemSettings", SystemSettingsSchema);
const AuditLog = mongoose.model("AuditLog", AuditLogSchema);
const FraudLog = mongoose.model("FraudLog", FraudLogSchema);
const WishlistNotification = mongoose.model("WishlistNotification", WishlistNotificationSchema);

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

/* NEW: Audit Logger */
async function logAudit(req, userEmail, role, action, status = "success", details = "") {
  try {
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress || "unknown";
    const userAgent = req.headers["user-agent"] || "unknown";
    await AuditLog.create({ userEmail, role, action, ip, userAgent, status, details });
  } catch (err) { console.error("Audit log error:", err.message); }
}

/* NEW: Sentiment Analysis Helper */
function analyzeSentiment(rating) {
  if (rating >= 4.5) return 1.0;
  if (rating >= 4.0) return 0.7;
  if (rating >= 3.0) return 0.3;
  if (rating >= 2.0) return -0.3;
  return -0.7;
}

/* =========================
   GOOGLE OAUTH
========================= */
passport.use(new GoogleStrategy({
  clientID: process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL: process.env.NODE_ENV === "production"
    ? "https://shelfsense-ai-lptz.onrender.com/auth/google/callback"
    : "http://localhost:3000/auth/google/callback"
}, async (accessToken, refreshToken, profile, done) => {
  try {
    let store = await Store.findOne({ googleId: profile.id });
    if (!store) {
      store = await Store.findOne({ ownerEmail: profile.emails[0].value });
      if (store) {
        store.googleId = profile.id;
        store.avatar = profile.photos[0]?.value;
        await store.save();
      } else {
        store = await Store.create({
          name: `${profile.displayName}'s Store`,
          ownerName: profile.displayName,
          ownerEmail: profile.emails[0].value,
          googleId: profile.id,
          avatar: profile.photos[0]?.value,
          plan: "free"
        });
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
   INIT
========================= */
async function init() {
  if (!(await User.findOne({ role: "superadmin" }))) {
    const hashedPassword = await bcrypt.hash("superadmin123", 12);
    await User.create({
      role: "superadmin",
      fname: "Super", lname: "Admin",
      email: "superadmin@shelfsense.ai",
      password: hashedPassword
    });
    console.log("✅ Super admin created");
  }
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
   JWT AUTH (with blacklist check)
========================= */
function auth(role) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token provided" });
    const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;

    // Check blacklist
    if (tokenBlacklist.has(token)) {
      return res.status(401).json({ message: "Token has been revoked. Please login again." });
    }

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (role && decoded.role !== role && decoded.role !== "superadmin") {
        return res.status(403).json({ message: "Forbidden" });
      }
      req.user = decoded;
      req.token = token;
      next();
    } catch (err) {
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };
}

/* =========================
   GOOGLE OAUTH ROUTES
========================= */
app.get("/auth/google", (req, res, next) => {
  const type = req.query.type || "store";
  res.cookie("oauthType", type, { maxAge: 5 * 60 * 1000, httpOnly: true });
  passport.authenticate("google", { scope: ["profile", "email"] })(req, res, next);
});

app.get("/auth/google/callback",
  passport.authenticate("google", { failureRedirect: "/login.html?error=google_failed" }),
  async (req, res) => {
    try {
      const oauthType = req.cookies?.oauthType || "store";
      res.clearCookie("oauthType");

      if (oauthType === "customer") {
        const profile = req.user;
        const email = profile.ownerEmail;
        const name = profile.ownerName || "";
        const nameParts = name.split(" ");
        const fname = nameParts[0] || "Customer";
        const lname = nameParts.slice(1).join(" ") || "";

        let customer = await User.findOne({ email: email.toLowerCase() });
        if (!customer) {
          customer = await User.create({
            fname, lname,
            email: email.toLowerCase(),
            role: "customer",
            googleId: profile.googleId,
            avatar: profile.avatar
          });
        } else {
          if (!customer.googleId) {
            customer.googleId = profile.googleId;
            await customer.save();
          }
        }

        const token = jwt.sign(
          { id: customer._id, role: "customer", email: customer.email, fname: customer.fname },
          process.env.JWT_SECRET, { expiresIn: "24h" }
        );
        await logAudit(req, customer.email, "customer", "GOOGLE_LOGIN");
        return res.redirect(`/customer.html?token=${token}`);
      }

      const store = req.user;
      const token = jwt.sign(
        { id: store._id, role: "admin", email: store.ownerEmail, fname: store.ownerName, storeId: store._id, storeName: store.name, plan: store.plan },
        process.env.JWT_SECRET, { expiresIn: "24h" }
      );
      await logAudit(req, store.ownerEmail, "admin", "GOOGLE_LOGIN");
      const isNewStore = !store.address && store.name.includes("'s Store");
      if (isNewStore) res.redirect(`/onboarding.html?token=${token}&new=true`);
      else res.redirect(`/admin.html?token=${token}`);

    } catch (err) {
      console.error("OAuth callback error:", err);
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
    if (!storeName || !ownerName || !email || !password) return res.status(400).json({ message: "All fields are required" });
    if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (await Store.findOne({ ownerEmail: email.toLowerCase() })) return res.status(400).json({ message: "An account with this email already exists" });
    const hashedPassword = await bcrypt.hash(password, 12);
    const store = await Store.create({ name: storeName, ownerName, ownerEmail: email.toLowerCase(), password: hashedPassword, plan: plan || "free", alertEmail: email.toLowerCase() });
    await seedStoreInventory(store._id);
    const baseUrl = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    await sendAlert("Welcome to ShelfSense AI! 🎉", `Hi ${ownerName}!<br><br>Your store <strong>${storeName}</strong> has been created.<br><br><strong>Login:</strong> <a href="${baseUrl}/login.html">${baseUrl}/login.html</a><br><br>Welcome aboard!`, false, email);
    const token = jwt.sign({ id: store._id, role: "admin", email: store.ownerEmail, fname: ownerName, storeId: store._id, storeName: store.name, plan: store.plan }, process.env.JWT_SECRET, { expiresIn: "24h" });
    await logAudit(req, email, "admin", "STORE_REGISTERED", "success", `Store: ${storeName}`);
    res.json({ message: "Store created successfully!", token, storeId: store._id });
  } catch (err) { console.error("Register error:", err.message); res.status(500).json({ message: "Server error" }); }
});

/* =========================
   STORE LOGIN
========================= */
app.post("/login-store", loginLimiter, async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ message: "Email and password required" });
    const store = await Store.findOne({ ownerEmail: email.toLowerCase() });
    if (!store) {
      trackSuspiciousIP(req);
      await logAudit(req, email, "admin", "LOGIN_FAILED", "failed", "Account not found");
      return res.status(401).json({ message: "Invalid credentials" });
    }
    if (store.lockUntil && store.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((store.lockUntil - Date.now()) / 60000);
      await logAudit(req, email, "admin", "LOGIN_BLOCKED", "failed", `Account locked for ${minutesLeft} minutes`);
      return res.status(423).json({ message: `Account locked. Try again in ${minutesLeft} minutes` });
    }
    const passwordMatch = await bcrypt.compare(password, store.password);
    if (!passwordMatch) {
      store.loginAttempts += 1;
      if (store.loginAttempts >= 5) { store.lockUntil = new Date(Date.now() + 30 * 60 * 1000); store.loginAttempts = 0; }
      await store.save();
      trackSuspiciousIP(req);
      await logAudit(req, email, "admin", "LOGIN_FAILED", "failed", "Wrong password");
      return res.status(401).json({ message: "Invalid credentials" });
    }
    store.loginAttempts = 0; store.lockUntil = null; await store.save();
await logAudit(req, email, "admin", "LOGIN_SUCCESS");
if (store.twoFactorEnabled) {
  const otp = generateOTP();
  otpStore.set(store.ownerEmail.toLowerCase(), {
    otp, name: store.ownerName,
    expires: Date.now() + 5 * 60 * 1000,
    storeData: { id: store._id, role: "admin", email: store.ownerEmail, fname: store.ownerName, storeId: store._id, storeName: store.name, plan: store.plan }
  });
  await sendOTPEmail(store.ownerEmail, otp, store.ownerName);
  return res.json({ requireOTP: true, email: store.ownerEmail });
}
const token = jwt.sign({ id: store._id, role: "admin", email: store.ownerEmail, fname: store.ownerName, storeId: store._id, storeName: store.name, plan: store.plan }, process.env.JWT_SECRET, { expiresIn: "24h" });
res.json({ token, role: "admin", fname: store.ownerName, storeName: store.name, plan: store.plan });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   CUSTOMER AUTH
========================= */
app.post("/signup", signupLimiter, async (req, res) => {
  try {
    const { fname, lname, email, password } = req.body;
    if (!fname || !lname || !email || !password) return res.status(400).json({ message: "All fields required" });
    if (password.length < 6) return res.status(400).json({ message: "Password must be at least 6 characters" });
    if (await User.findOne({ email: email.toLowerCase() })) return res.status(400).json({ message: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ fname, lname, email: email.toLowerCase(), password: hashedPassword });
    await logAudit(req, email, "customer", "CUSTOMER_REGISTERED");
    res.json({ message: "Account created successfully" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) return res.status(400).json({ message: "Username and password required" });
    const user = await User.findOne({ email: username.toLowerCase() });
    if (!user) {
      trackSuspiciousIP(req);
      await logAudit(req, username, "unknown", "LOGIN_FAILED", "failed", "Account not found");
      return res.status(401).json({ message: "Invalid credentials" });
    }
    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ message: `Account locked. Try again in ${minutesLeft} minutes` });
    }
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) { user.lockUntil = new Date(Date.now() + 30 * 60 * 1000); user.loginAttempts = 0; }
      await user.save();
      trackSuspiciousIP(req);
      await logAudit(req, username, user.role, "LOGIN_FAILED", "failed", "Wrong password");
      return res.status(401).json({ message: "Invalid credentials" });
    }
    user.loginAttempts = 0; user.lockUntil = null; await user.save();
await logAudit(req, user.email, user.role, "LOGIN_SUCCESS");
if (user.twoFactorEnabled) {
  const otp = generateOTP();
  otpStore.set(user.email.toLowerCase(), {
    otp, name: user.fname || user.email,
    expires: Date.now() + 5 * 60 * 1000,
    userData: { id: user._id, role: user.role, email: user.email, fname: user.fname }
  });
  await sendOTPEmail(user.email, otp, user.fname || "User");
  return res.json({ requireOTP: true, email: user.email });
}
const token = jwt.sign({ id: user._id, role: user.role, email: user.email, fname: user.fname }, process.env.JWT_SECRET, { expiresIn: "24h" });
res.json({ token, role: user.role, fname: user.fname });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   LOGOUT (with token blacklisting)
========================= */
app.post("/logout", async (req, res) => {
  try {
    const authHeader = req.headers.authorization;
    if (authHeader) {
      const token = authHeader.startsWith("Bearer ") ? authHeader.slice(7) : authHeader;
      blacklistToken(token);
      try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        await logAudit(req, decoded.email, decoded.role, "LOGOUT");
      } catch(e) {}
    }
  } catch(e) {}
  req.logout(() => {});
  res.json({ message: "Logged out successfully" });
});

/* =========================
   FORGOT/RESET PASSWORD
========================= */
app.post("/forgot-password", async (req, res) => {
  try {
    const { email } = req.body;
    if (!email || !email.includes("@")) return res.status(400).json({ error: "Please enter a valid email address" });
    const store = await Store.findOne({ ownerEmail: email.toLowerCase() });
    const customer = await User.findOne({ email: email.toLowerCase() });
    if (!store && !customer) return res.json({ message: "If that email is registered, a reset link has been sent." });
    const resetToken = crypto.randomBytes(32).toString("hex");
    const resetExpiry = new Date(Date.now() + 60 * 60 * 1000);
    if (store) { store.resetToken = resetToken; store.resetTokenExpiry = resetExpiry; await store.save(); }
    else { customer.resetToken = resetToken; customer.resetTokenExpiry = resetExpiry; await customer.save(); }
    const baseUrl = process.env.BASE_URL || `http://localhost:${process.env.PORT || 3000}`;
    const resetLink = `${baseUrl}/reset-password.html?token=${resetToken}`;
    await emailTransporter.sendMail({
      from: `"ShelfSense AI" <${process.env.ALERT_EMAIL}>`,
      to: email,
      subject: "Reset Your ShelfSense Password",
      html: `<div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto"><div style="background:#7c3aed;padding:20px;border-radius:10px 10px 0 0"><h1 style="color:white;margin:0;font-size:1.3rem">🔐 ShelfSense AI — Password Reset</h1></div><div style="background:#f8fafc;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e2e8f0"><p>Click below to reset your password. Expires in 1 hour.</p><a href="${resetLink}" style="display:inline-block;background:#7c3aed;color:white;padding:12px 24px;border-radius:8px;text-decoration:none;font-weight:bold;margin:16px 0">Reset My Password</a><p style="color:#666;font-size:13px">If you did not request this, ignore this email.</p></div></div>`
    });
    await logAudit(req, email, "unknown", "PASSWORD_RESET_REQUESTED");
    res.json({ message: "If that email is registered, a reset link has been sent." });
  } catch (err) { console.error("Forgot password error:", err); res.status(500).json({ error: "Something went wrong. Please try again." }); }
});

app.post("/reset-password", async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    if (!token || !newPassword) return res.status(400).json({ error: "Token and password required" });
    if (newPassword.length < 8) return res.status(400).json({ error: "Password must be at least 8 characters" });
    const now = new Date();
    let account = await Store.findOne({ resetToken: token, resetTokenExpiry: { $gt: now } });
    if (!account) account = await User.findOne({ resetToken: token, resetTokenExpiry: { $gt: now } });
    if (!account) return res.status(400).json({ error: "Reset link is invalid or has expired." });
    account.password = await bcrypt.hash(newPassword, 12);
    account.resetToken = undefined;
    account.resetTokenExpiry = undefined;
    await account.save();
    await logAudit(req, account.ownerEmail || account.email, account.role || "unknown", "PASSWORD_RESET_SUCCESS");
    res.json({ message: "Password reset successfully! You can now log in." });
  } catch (err) { console.error("Reset password error:", err); res.status(500).json({ error: "Something went wrong. Please try again." }); }
});

/* =========================
   ONBOARDING
========================= */
app.post("/complete-onboarding", auth("admin"), async (req, res) => {
  try {
    const { storeName, address, phone, openingTime, closingTime, weatherCity } = req.body;
    await Store.updateOne({ _id: req.user.storeId }, { $set: { name: storeName, address, phone, openingTime, closingTime, weatherCity } });
    await logAudit(req, req.user.email, "admin", "ONBOARDING_COMPLETE");
    res.json({ message: "Store setup complete!" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   SHOP ITEMS
========================= */
app.get("/shop-items", auth("customer"), async (req, res) => {
  try {
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
        avgRating: i.avgRating || 0, totalRatings: i.totalRatings || 0,
        sentimentScore: i.sentimentScore || 0
      };
    });
    res.json(view);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* NEW: Track product view */
app.post("/track-view", auth("customer"), async (req, res) => {
  try {
    const { itemKey } = req.body;
    await Item.updateOne({ key: itemKey }, { $inc: { viewCount: 1 } });
    res.json({ ok: true });
  } catch (err) { res.json({ ok: false }); }
});

/* NEW: Save wishlist to DB */
app.post("/save-wishlist", auth("customer"), async (req, res) => {
  try {
    const { wishlist } = req.body;
    await User.updateOne({ _id: req.user.id }, { $set: { wishlist } });

    // Create wishlist notifications for out-of-stock items
    for (const itemKey of wishlist) {
      const item = await Item.findOne({ key: itemKey });
      if (item && item.stock === 0) {
        const existing = await WishlistNotification.findOne({ userId: req.user.id, itemKey, notified: false });
        if (!existing) {
          await WishlistNotification.create({
            userId: req.user.id,
            userEmail: req.user.email,
            itemKey,
            itemName: item.name
          });
        }
      }
    }
    res.json({ message: "Wishlist saved" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   CHECKOUT (with fraud detection)
========================= */
app.post("/checkout", auth("customer"), async (req, res) => {
  try {
    const { cart, storeId } = req.body;
    if (!cart || typeof cart !== "object") return res.status(400).json({ message: "Invalid cart" });

    // FRAUD DETECTION — check for suspicious order patterns
    const ip = req.headers["x-forwarded-for"] || req.socket.remoteAddress;
    const recentOrders = await Order.find({
      userId: req.user.id,
      createdAt: { $gte: new Date(Date.now() - 5 * 60 * 1000) }
    });

    let flaggedAsFraud = false;
    if (recentOrders.length >= 5) {
      flaggedAsFraud = true;
      await FraudLog.create({
        userId: req.user.id,
        userEmail: req.user.email,
        reason: "5+ orders in 5 minutes",
        ip
      });
      await logAudit(req, req.user.email, "customer", "FRAUD_DETECTED", "warning", "Too many orders in short time");
    }

    const adjusted = {}, itemNames = {}, notices = [];
    let totalItems = 0, totalAmount = 0;
    for (const key in cart) {
      if (!validateInput(key, 50)) continue;
      const item = await Item.findOne({ key, storeId: storeId || { $exists: true } });
      if (!item) continue;
      const qty = Math.max(0, Math.min(parseInt(cart[key]) || 0, 100));

      // Fraud: single item quantity > 50
      if (qty > 50) {
        flaggedAsFraud = true;
        await FraudLog.create({ userId: req.user.id, userEmail: req.user.email, reason: `Unusual quantity: ${qty} of ${item.name}`, ip });
      }

      const allowed = Math.min(qty, item.stock);
      adjusted[key] = allowed; itemNames[key] = item.name;
      totalItems += allowed;
      totalAmount += (item.onSale ? item.salePrice : item.price || 99) * allowed;
      if (qty > item.stock) notices.push(`${item.name}: only ${item.stock} available`);
      await Item.updateOne({ key, storeId: item.storeId }, {
        $inc: { stock: -allowed },
        $set: { previousStock: item.stock },
        $push: { salesHistory: { $each: [allowed], $slice: -30 } }
      });
    }

    // Fraud: total amount > ₹50,000
    if (totalAmount > 50000) {
      flaggedAsFraud = true;
      await FraudLog.create({ userId: req.user.id, userEmail: req.user.email, reason: `Unusually high order: ₹${totalAmount}`, ip });
    }

    await Order.create({
      storeId, userId: req.user.id, userEmail: req.user.email,
      cart: adjusted, itemNames, totalItems, totalAmount,
      paymentStatus: "paid", flaggedAsFraud,
      time: new Date().toLocaleString()
    });

    if (flaggedAsFraud) {
      await sendAlert("🚨 Suspicious Order Detected", `Order from <strong>${req.user.email}</strong> flagged as potentially fraudulent. Amount: ₹${totalAmount}`, true);
    }

    res.json({ message: "Order placed successfully", notices, flaggedAsFraud });
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
    const order = await razorpay.orders.create({ amount: totalAmount * 100, currency: "INR", receipt: `order_${Date.now()}`, notes: { userId: req.user.id, userEmail: req.user.email } });
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (err) { console.error("Payment error:", err.message); res.status(500).json({ message: "Failed to create payment order" }); }
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
      await Item.updateOne({ key, storeId: item.storeId }, { $inc: { stock: -allowed }, $push: { salesHistory: { $each: [allowed], $slice: -30 } } });
    }
    await Order.create({ storeId, userId: req.user.id, userEmail: req.user.email, cart: adjusted, itemNames, totalItems, totalAmount, paymentId: razorpay_payment_id, paymentStatus: "paid", time: new Date().toLocaleString() });
    await logAudit(req, req.user.email, "customer", "PAYMENT_SUCCESS", "success", `₹${totalAmount}`);
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
   RATINGS (with sentiment)
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
    const sentiment = analyzeSentiment(avg);
    await Item.updateOne({ key: itemKey, storeId: item.storeId }, {
      $set: { avgRating: Math.round(avg * 10) / 10, totalRatings: allRatings.length, sentimentScore: sentiment }
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
   ADMIN ROUTES
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

app.post("/admin/update-threshold", auth("admin"), async (req, res) => {
  try {
    const { key, minStockLevel } = req.body;
    const storeId = req.user.storeId;
    const min = parseInt(minStockLevel);
    if (isNaN(min) || min < 1 || min > 100) return res.status(400).json({ message: "Threshold must be between 1 and 100" });
    await Item.updateOne({ key, storeId }, { $set: { minStockLevel: min } });
    res.json({ message: `Alert threshold set to ${min} units` });
  } catch(err) { res.status(500).json({ message: "Server error" }); }
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
    for (const key in defaults) { await Item.updateOne({ key, storeId }, { $set: { stock: defaults[key], salesHistory: [] } }); }
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
    await Store.updateOne({ _id: req.user.storeId }, { $set: { openingTime, closingTime, name: storeName, alertEmail, weatherCity, address, phone } });
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
    const imageBuffer = fs.readFileSync(req.file.path);
    const imageBase64 = imageBuffer.toString("base64");
    const urlSetting = await SystemSettings.findOne({ key: "ML_SERVICE_URL" });
    const ML_SERVICE_URL = (urlSetting && urlSetting.value) || process.env.ML_SERVICE_URL || "http://127.0.0.1:5001";
    const mlResponse = await fetch(`${ML_SERVICE_URL}/process-shelf-image`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ imageBase64, total_slots: totalSlots, shelf_id: shelfId })
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
   ML URL
========================= */
app.get("/admin/ml-url", auth("admin"), async (req, res) => {
  try {
    const setting = await SystemSettings.findOne({ key: "ML_SERVICE_URL" });
    const url = setting ? setting.value : (process.env.ML_SERVICE_URL || "http://127.0.0.1:5001");
    res.json({ url });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/ml-url", auth("admin"), async (req, res) => {
  try {
    const { url } = req.body;
    if (!url || !url.startsWith("http")) return res.status(400).json({ message: "Invalid URL" });
    await SystemSettings.findOneAndUpdate(
      { key: "ML_SERVICE_URL" },
      { key: "ML_SERVICE_URL", value: url },
      { upsert: true, new: true }
    );
    res.json({ message: "ML Service URL updated successfully!" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   SALES ANALYTICS
========================= */
app.get("/admin/analytics", auth("admin"), async (req, res) => {
  try {
    const storeId = req.user.storeId;
    const orders = await Order.find({ storeId }).sort({ createdAt: -1 });

    // Total stats
    const totalRevenue = orders.reduce((sum, o) => sum + (o.totalAmount || 0), 0);
    const totalOrders = orders.length;
    const avgOrderValue = totalOrders > 0 ? totalRevenue / totalOrders : 0;

    // Best selling products
    const productQty = {};
    const productNames = {};
    orders.forEach(order => {
      Object.entries(order.cart || {}).forEach(([key, qty]) => {
        productQty[key] = (productQty[key] || 0) + qty;
        if (order.itemNames?.[key]) productNames[key] = order.itemNames[key];
      });
    });
    const bestSellers = Object.entries(productQty)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([key, qty]) => ({ name: productNames[key] || key, qty }));
    const topProduct = bestSellers[0]?.name || "N/A";

    // Revenue and orders by day (last 14 days)
    const last14 = Array.from({ length: 14 }, (_, i) => {
      const d = new Date();
      d.setDate(d.getDate() - (13 - i));
      return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short" });
    });

    const revenueByDay = last14.map(date => {
      const dayOrders = orders.filter(o => {
        const d = new Date(o.createdAt);
        return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short" }) === date;
      });
      return { date, revenue: dayOrders.reduce((s, o) => s + (o.totalAmount || 0), 0) };
    });

    const ordersByDay = last14.map(date => {
      const count = orders.filter(o => {
        const d = new Date(o.createdAt);
        return d.toLocaleDateString("en-IN", { day: "2-digit", month: "short" }) === date;
      }).length;
      return { date, count };
    });

    // Sales by day of week (0=Sun to 6=Sat)
    const salesByDay = [0,1,2,3,4,5,6].map(day =>
      orders.filter(o => new Date(o.createdAt).getDay() === day).length
    );

    // Recent 10 orders
    const recentOrders = orders.slice(0, 10);

    res.json({ totalRevenue, totalOrders, avgOrderValue, topProduct, bestSellers, revenueByDay, ordersByDay, salesByDay, recentOrders });
  } catch(err) {
    console.error("Analytics error:", err.message);
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   2FA ROUTES
========================= */
app.post("/admin/toggle-2fa", auth("admin"), async (req, res) => {
  try {
    const store = await Store.findById(req.user.storeId);
    if (!store) return res.status(404).json({ message: "Store not found" });
    store.twoFactorEnabled = !store.twoFactorEnabled;
    await store.save();
    await logAudit(req, req.user.email, "admin", store.twoFactorEnabled ? "2FA_ENABLED" : "2FA_DISABLED");
    res.json({ enabled: store.twoFactorEnabled, message: `2FA ${store.twoFactorEnabled ? "enabled" : "disabled"} successfully` });
  } catch(err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/customer/toggle-2fa", auth("customer"), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    if (!user) return res.status(404).json({ message: "User not found" });
    user.twoFactorEnabled = !user.twoFactorEnabled;
    await user.save();
    await logAudit(req, req.user.email, "customer", user.twoFactorEnabled ? "2FA_ENABLED" : "2FA_DISABLED");
    res.json({ enabled: user.twoFactorEnabled, message: `2FA ${user.twoFactorEnabled ? "enabled" : "disabled"} successfully` });
  } catch(err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/2fa-status", auth("admin"), async (req, res) => {
  try {
    const store = await Store.findById(req.user.storeId);
    res.json({ enabled: store?.twoFactorEnabled || false });
  } catch(err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/customer/2fa-status", auth("customer"), async (req, res) => {
  try {
    const user = await User.findById(req.user.id);
    res.json({ enabled: user?.twoFactorEnabled || false });
  } catch(err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/verify-otp", async (req, res) => {
  try {
    const { email, otp } = req.body;
    if (!email || !otp) return res.status(400).json({ message: "Email and OTP required" });
    const record = otpStore.get(email.toLowerCase());
    if (!record) return res.status(400).json({ message: "OTP expired. Please login again." });
    if (Date.now() > record.expires) {
      otpStore.delete(email.toLowerCase());
      return res.status(400).json({ message: "OTP has expired. Please login again." });
    }
    if (record.otp !== otp.toString()) return res.status(400).json({ message: "Invalid OTP. Please try again." });
    otpStore.delete(email.toLowerCase());
    let token;
    if (record.storeData) {
      token = jwt.sign(record.storeData, process.env.JWT_SECRET, { expiresIn: "24h" });
      await logAudit(req, email, "admin", "LOGIN_SUCCESS_2FA");
      return res.json({ token, role: "admin", fname: record.storeData.fname, storeName: record.storeData.storeName, plan: record.storeData.plan });
    } else {
      token = jwt.sign(record.userData, process.env.JWT_SECRET, { expiresIn: "24h" });
      await logAudit(req, email, record.userData.role, "LOGIN_SUCCESS_2FA");
      return res.json({ token, role: record.userData.role, fname: record.userData.fname });
    }
  } catch(err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/resend-otp", async (req, res) => {
  try {
    const { email } = req.body;
    const record = otpStore.get(email.toLowerCase());
    if (!record) return res.status(400).json({ message: "Session expired. Please login again." });
    const otp = generateOTP();
    record.otp = otp;
    record.expires = Date.now() + 5 * 60 * 1000;
    otpStore.set(email.toLowerCase(), record);
    await sendOTPEmail(email, otp, record.name);
    res.json({ message: "New OTP sent!" });
  } catch(err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   AUDIT LOGS API
========================= */
app.get("/admin/audit-logs", auth("admin"), async (req, res) => {
  try {
    const logs = await AuditLog.find({ userEmail: req.user.email })
      .sort({ createdAt: -1 }).limit(100);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/fraud-logs", auth("admin"), async (req, res) => {
  try {
    const logs = await FraudLog.find({ userEmail: { $exists: true } })
      .sort({ createdAt: -1 }).limit(50);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/security-logs", auth("admin"), async (req, res) => {
  try {
    const logs = await SecurityLog.find().sort({ time: -1 }).limit(50);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
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
      .map(f => ({ name: f.name, address: f.address, stock: f.inventory[product], distance: calculateDistance(parseFloat(lat), parseFloat(lng), f.lat, f.lng).toFixed(2), lat: f.lat, lng: f.lng }))
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
    const totalFraudFlags = await FraudLog.countDocuments();
    const totalAuditLogs = await AuditLog.countDocuments();
    const planCounts = await Store.aggregate([{ $group: { _id: "$plan", count: { $sum: 1 } } }]);
    res.json({ totalStores, totalOrders, totalItems, totalFraudFlags, totalAuditLogs, planCounts });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/superadmin/audit-logs", auth("superadmin"), async (req, res) => {
  try {
    const logs = await AuditLog.find().sort({ createdAt: -1 }).limit(200);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/superadmin/fraud-logs", auth("superadmin"), async (req, res) => {
  try {
    const logs = await FraudLog.find().sort({ createdAt: -1 }).limit(100);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/superadmin/update-plan", auth("superadmin"), async (req, res) => {
  try {
    const { storeId, plan, isActive } = req.body;
    const update = {};
    if (plan !== undefined) update.plan = plan;
    if (isActive !== undefined) update.isActive = isActive;
    await Store.updateOne({ _id: storeId }, { $set: update });
    res.json({ message: "Store updated successfully" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================================
   15 AI AGENTS
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
            await logAgent(store._id, "Anomaly Detection Agent", `🚨 POSSIBLE THEFT: ${item.name} — Unusual stock drop outside shop hours`, { item: item.name, stock: recentDrop, zScore: zScore.toFixed(2) }, "critical");
            await sendAlert(`POSSIBLE THEFT: ${item.name}`, `🚨 Unusual stock drop detected outside shop hours at <strong>${store.name}</strong>!`, true, store.alertEmail);
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

/* =========================================
   NEW AGENTS (11-15)
========================================= */

/* AGENT 11 — SENTIMENT ANALYSIS */
cron.schedule("0 0 2 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id, totalRatings: { $gte: 3 } });
      for (const item of items) {
        const sentiment = analyzeSentiment(item.avgRating || 0);
        await Item.updateOne({ _id: item._id }, { $set: { sentimentScore: sentiment } });
        if (sentiment < -0.3) {
          await logAgent(store._id, "Sentiment Analysis Agent",
            `😟 Negative sentiment detected for ${item.name} — Avg rating: ${item.avgRating?.toFixed(1)}⭐ (${item.totalRatings} reviews). Consider quality review or discount.`,
            { item: item.name, avgRating: item.avgRating, sentiment }, "warning");
          await sendAlert(`Negative Reviews: ${item.name}`,
            `<strong>${item.name}</strong> has a low average rating of ${item.avgRating?.toFixed(1)}⭐ from ${item.totalRatings} reviews at <strong>${store.name}</strong>. Consider reviewing product quality.`,
            false, store.alertEmail);
        } else if (sentiment > 0.7) {
          await logAgent(store._id, "Sentiment Analysis Agent",
            `😊 Excellent sentiment for ${item.name} — Avg rating: ${item.avgRating?.toFixed(1)}⭐ (${item.totalRatings} reviews). Consider increasing stock.`,
            { item: item.name, avgRating: item.avgRating, sentiment }, "info");
        }
      }
    }
  } catch (err) { console.error("Sentiment Agent error:", err.message); }
});

/* AGENT 12 — DEMAND SURGE */
cron.schedule("*/2 * * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        // Detect if view count jumped significantly in last 2 minutes
        if (item.viewCount > 50 && item.stock <= item.minStockLevel * 2) {
          await logAgent(store._id, "Demand Surge Agent",
            `📈 Demand surge detected for ${item.name}! ${item.viewCount} views but only ${item.stock} units left. Reorder recommended immediately.`,
            { item: item.name, viewCount: item.viewCount, stock: item.stock }, "warning");
          // Reset view counter after alert
          await Item.updateOne({ _id: item._id }, { $set: { viewCount: 0 } });
        }
        // Detect surge from cart additions
        if (item.cartCount > 20 && item.stock <= item.minStockLevel) {
          await logAgent(store._id, "Demand Surge Agent",
            `🛒 Cart surge for ${item.name}! Added to cart ${item.cartCount} times. Stock critically low at ${item.stock} units.`,
            { item: item.name, cartCount: item.cartCount, stock: item.stock }, "critical");
          await sendAlert(`Demand Surge: ${item.name}`,
            `<strong>${item.name}</strong> has been added to cart ${item.cartCount} times with only ${item.stock} units left at <strong>${store.name}</strong>!`,
            true, store.alertEmail);
          await Item.updateOne({ _id: item._id }, { $set: { cartCount: 0 } });
        }
      }
    }
  } catch (err) { console.error("Demand Surge Agent error:", err.message); }
});

/* AGENT 13 — FRAUD DETECTION */
cron.schedule("*/1 * * * *", async () => {
  try {
    // Detect multiple orders from same user in short time
    const recentOrders = await Order.find({
      createdAt: { $gte: new Date(Date.now() - 10 * 60 * 1000) }
    });
    const userOrderCount = {};
    recentOrders.forEach(o => {
      const uid = o.userId?.toString();
      if (uid) userOrderCount[uid] = (userOrderCount[uid] || 0) + 1;
    });
    for (const [userId, count] of Object.entries(userOrderCount)) {
      if (count >= 5) {
        const user = await User.findById(userId);
        if (user) {
          const existing = await FraudLog.findOne({
            userId, createdAt: { $gte: new Date(Date.now() - 10 * 60 * 1000) }
          });
          if (!existing) {
            await FraudLog.create({
              userId, userEmail: user.email,
              reason: `${count} orders in 10 minutes — automated fraud detection`,
              amount: 0
            });
            // Find which store this affects
            const order = recentOrders.find(o => o.userId?.toString() === userId);
            if (order?.storeId) {
              await logAgent(order.storeId, "Fraud Detection Agent",
                `🚨 FRAUD ALERT: ${user.email} placed ${count} orders in 10 minutes. Account flagged for review.`,
                { userEmail: user.email, orderCount: count }, "critical");
            }
          }
        }
      }
    }
  } catch (err) { console.error("Fraud Detection Agent error:", err.message); }
});

/* AGENT 14 — AUTO DISCOUNT (slow-moving products) */
cron.schedule("0 0 10 * * *", async () => {
  try {
    const stores = await Store.find({ isActive: true });
    for (const store of stores) {
      const items = await Item.find({ storeId: store._id });
      for (const item of items) {
        const history = item.salesHistory || [];
        if (history.length < 7) continue;
        const lastWeekSales = history.slice(-7).reduce((a, b) => a + b, 0);
        // If item sold less than 2 units in last 7 days and stock > 15 — slow moving
        if (lastWeekSales < 2 && item.stock > 15 && !item.onSale && !item.autoDiscountApplied) {
          const discountPct = 15;
          const discountPrice = Math.round(item.price * (1 - discountPct / 100));
          await Item.updateOne({ _id: item._id }, {
            $set: { onSale: true, salePercent: discountPct, salePrice: discountPrice, autoDiscountApplied: true }
          });
          await logAgent(store._id, "Auto Discount Agent",
            `🏷️ Auto-discount applied to ${item.name}: ${discountPct}% off (sold only ${lastWeekSales} units last week, ${item.stock} units in stock)`,
            { item: item.name, discount: discountPct, salesLastWeek: lastWeekSales }, "info");
        }
        // Remove auto-discount if item starts selling well again
        if (lastWeekSales >= 5 && item.autoDiscountApplied) {
          await Item.updateOne({ _id: item._id }, {
            $set: { onSale: false, salePercent: 0, salePrice: item.price, autoDiscountApplied: false }
          });
          await logAgent(store._id, "Auto Discount Agent",
            `✅ Auto-discount removed from ${item.name} — sales recovered (${lastWeekSales} units last week)`,
            { item: item.name, salesLastWeek: lastWeekSales }, "info");
        }
      }
    }
  } catch (err) { console.error("Auto Discount Agent error:", err.message); }
});

/* AGENT 15 — SMART WISHLIST NOTIFICATION */
cron.schedule("0 */30 * * * *", async () => {
  try {
    // Find all unnotified wishlist items that are now back in stock
    const notifications = await WishlistNotification.find({ notified: false });
    for (const notif of notifications) {
      const item = await Item.findOne({ key: notif.itemKey });
      if (item && item.stock > 0) {
        // Send email notification
        await emailTransporter.sendMail({
          from: `"ShelfSense AI 🤖" <${process.env.ALERT_EMAIL}>`,
          to: notif.userEmail,
          subject: `✅ ${notif.itemName} is back in stock!`,
          html: `
            <div style="font-family:Arial,sans-serif;max-width:500px;margin:0 auto">
              <div style="background:#6366f1;padding:20px;border-radius:10px 10px 0 0">
                <h1 style="color:white;margin:0;font-size:1.2rem">🛍️ ShelfSense AI — Back In Stock!</h1>
              </div>
              <div style="background:#f8fafc;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e2e8f0">
                <p style="font-size:1rem;color:#1e293b">Good news! <strong>${notif.itemName}</strong> is back in stock and ready for you to purchase.</p>
                <p style="color:#6366f1;font-weight:bold">Current stock: ${item.stock} units available</p>
                <p style="font-size:0.85rem;color:#94a3b8">Hurry before it sells out again!</p>
              </div>
            </div>`
        });
        await WishlistNotification.updateOne({ _id: notif._id }, { $set: { notified: true } });
        await logAgent(null, "Smart Notification Agent",
          `📧 Back-in-stock notification sent to ${notif.userEmail} for ${notif.itemName}`,
          { userEmail: notif.userEmail, item: notif.itemName }, "info");
      }
    }
  } catch (err) { console.error("Smart Notification Agent error:", err.message); }
});

/* =========================
   DOWNLOAD STOCK EXCEL
========================= */
app.get("/admin/download-stock", auth("admin"), async (req, res) => {
  try {
    const storeId = req.user.storeId;
    const items = await Item.find({ storeId });
    const pendingOrders = await PurchaseOrder.find({ storeId, status: { $in: ["pending", "sent"] } });
    const pendingKeys = pendingOrders.map(o => o.itemKey);

    // Build CSV content
    const headers = [
      "Item Name",
      "Category",
      "Current Stock",
      "Min Stock Level",
      "Availability Status",
      "Stock Warning",
      "Auto Reordered by Agent",
      "Price (Rs.)",
      "On Sale",
      "Sale Discount (%)",
      "Sale Price (Rs.)",
      "Supplier",
      "Expiry Date"
    ];

    const rows = items.map(item => {
      const isOut = item.stock === 0;
      const isLow = item.stock > 0 && item.stock <= item.minStockLevel;
      const isHealthy = item.stock > item.minStockLevel;
      const availability = isOut ? "OUT OF STOCK" : isLow ? "LOW STOCK" : "IN STOCK";
      const warning = isOut ? "CRITICAL - Out of stock" : isLow ? "WARNING - Ending soon" : "OK";
      const reordered = pendingKeys.includes(item.key) ? "YES - Reorder Pending" : "No";
      const onSale = item.onSale ? "YES" : "No";
      const salePercent = item.onSale ? item.salePercent : 0;
      const salePrice = item.onSale ? item.salePrice : item.price;
      const expiry = item.expiryDate ? new Date(item.expiryDate).toLocaleDateString("en-IN") : "N/A";

      return [
        item.name,
        item.category || "general",
        item.stock,
        item.minStockLevel,
        availability,
        warning,
        reordered,
        item.price || 99,
        onSale,
        salePercent,
        salePrice,
        item.supplier || "N/A",
        expiry
      ];
    });

    // Convert to CSV
    const csvLines = [
      `ShelfSense AI - Stock Report for ${req.user.storeName || "Store"}`,
      `Generated on: ${new Date().toLocaleString("en-IN")}`,
      `Total Items: ${items.length}`,
      "",
      headers.join(","),
      ...rows.map(row => row.map(cell => `"${cell}"`).join(","))
    ];

    const csvContent = csvLines.join("\n");
    const filename = `ShelfSense_Stock_${new Date().toISOString().split("T")[0]}.csv`;

    res.setHeader("Content-Type", "text/csv");
    res.setHeader("Content-Disposition", `attachment; filename="${filename}"`);
    res.send(csvContent);

  } catch (err) {
    console.error("Download stock error:", err.message);
    res.status(500).json({ message: "Server error" });
  }
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
app.listen(PORT, "0.0.0.0", () => {
  console.log(`🚀 ShelfSense AI running at http://localhost:${PORT}`);
  console.log(`🔒 Security layer active — CSRF, JWT Blacklist, Audit Log, IP Detection`);
  console.log(`🤖 All 15 AI Agents initialized`);
  console.log(`💳 Razorpay active`);
  console.log(`📧 Email alerts active`);
  console.log(`🔐 Google OAuth active`);
  console.log(`🏪 Multi-tenant SaaS ready`);
});