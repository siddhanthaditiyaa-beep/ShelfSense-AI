/* =========================================
   RETAIL MART AGENTIC AI SYSTEM
   server.js — Main Backend
   With Complete Cybersecurity Layer
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

const { mapSlotsToProducts, updatePlanogram, getPlanogram } = require("./slotProductMapper");

const app = express();

/* =========================
   SECURITY LAYER 1 — HELMET
========================= */
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));

/* =========================
   SECURITY LAYER 2 — CORS
========================= */
const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error("Not allowed by CORS"));
    }
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

/* =========================
   SECURITY LAYER 3 — RATE LIMITING
========================= */
const generalLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,
  message: { message: "Too many requests, please try again later" },
  standardHeaders: true,
  legacyHeaders: false
});

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  message: { message: "Too many login attempts, please try again in 15 minutes" },
  standardHeaders: true,
  legacyHeaders: false
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 3,
  message: { message: "Too many signup attempts, please try again in an hour" },
  standardHeaders: true,
  legacyHeaders: false
});

app.use("/api", generalLimiter);

/* =========================
   BODY PARSING
========================= */
app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));

/* =========================
   SECURITY LAYER 4 — MONGO SANITIZE
========================= */
app.use(mongoSanitize());

/* =========================
   SECURITY LAYER 5 — REQUEST LOGGING
========================= */
app.use((req, res, next) => {
  const timestamp = new Date().toISOString();
  const ip = req.ip || req.connection.remoteAddress;
  console.log(`[${timestamp}] ${req.method} ${req.path} — IP: ${ip}`);

  const suspicious = [
    "<script", "javascript:", "eval(", "DROP TABLE",
    "$where", "../../", "passwd", "etc/shadow"
  ];

  const body = JSON.stringify(req.body || "");
  const query = JSON.stringify(req.query || "");

  suspicious.forEach(pattern => {
    if (body.includes(pattern) || query.includes(pattern)) {
      console.warn(`🚨 SUSPICIOUS REQUEST from ${ip}: ${pattern}`);
    }
  });

  next();
});

/* =========================
   STATIC FILES
========================= */
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

/* =========================
   IMAGE UPLOAD CONFIG
========================= */
if (!fs.existsSync("uploads")) fs.mkdirSync("uploads");

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads"),
  filename: (req, file, cb) => cb(null, Date.now() + path.extname(file.originalname))
});

const fileFilter = (req, file, cb) => {
  const allowedTypes = ["image/jpeg", "image/jpg", "image/png", "image/webp"];
  if (allowedTypes.includes(file.mimetype)) {
    cb(null, true);
  } else {
    cb(new Error("Only JPG, PNG and WEBP images are allowed"), false);
  }
};

const upload = multer({
  storage,
  fileFilter,
  limits: { fileSize: 10 * 1024 * 1024 }
});

/* =========================
   MONGODB CONNECTION
========================= */
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ Mongo error", err));

/* =========================
   SCHEMAS
========================= */
const UserSchema = new mongoose.Schema({
  role: { type: String, default: "customer", enum: ["customer", "admin"] },
  fname: { type: String, maxlength: 50 },
  lname: { type: String, maxlength: 50 },
  email: { type: String, unique: true, lowercase: true },
  password: String,
  loginAttempts: { type: Number, default: 0 },
  lockUntil: { type: Date, default: null },
  createdAt: { type: Date, default: Date.now }
});

const ItemSchema = new mongoose.Schema({
  key: String,
  name: { type: String, maxlength: 100 },
  stock: { type: Number, min: 0, max: 99999 },
  salesHistory: { type: [Number], default: [] }
});

const OrderSchema = new mongoose.Schema({ cart: Object, time: String });

const LogSchema = new mongoose.Schema({
  type: String, item: String, stock: Number, message: String, time: String
});

const ShelfScanSchema = new mongoose.Schema({
  shelf_id: String, imagePath: String, total_slots: Number,
  occupied_slots: Number, empty_slots: Number,
  occupied_slot_numbers: Array, empty_slot_numbers: Array,
  present_products: Array, missing_products: Array,
  detection_details: Array, stock_counts: Object,
  fill_percentage: Number, detectedAt: String
});

const FranchiseSchema = new mongoose.Schema({
  name: String, address: String, lat: Number, lng: Number, inventory: Object
});

const SecurityLogSchema = new mongoose.Schema({
  type: String, ip: String, path: String, message: String,
  time: { type: Date, default: Date.now }
});

/* =========================
   MODELS
========================= */
const User = mongoose.model("User", UserSchema);
const Item = mongoose.model("Item", ItemSchema);
const Order = mongoose.model("Order", OrderSchema);
const Log = mongoose.model("Log", LogSchema);
const ShelfScan = mongoose.model("ShelfScan", ShelfScanSchema);
const Franchise = mongoose.model("Franchise", FranchiseSchema);
const SecurityLog = mongoose.model("SecurityLog", SecurityLogSchema);

/* =========================
   INIT
========================= */
async function init() {
  if (!(await User.findOne({ role: "admin" }))) {
    const hashedPassword = await bcrypt.hash("admin123", 12);
    await User.create({
      role: "admin", fname: "Store", lname: "Admin",
      email: "admin", password: hashedPassword
    });
    console.log("✅ Admin user created");
  }

  if ((await Item.countDocuments()) === 0) {
    await Item.insertMany([
      { key: "chocolates", name: "Chocolates", stock: 5, salesHistory: [2,3,2,4,3] },
      { key: "biscuits", name: "Biscuits", stock: 8, salesHistory: [1,2,3,2,1] },
      { key: "chips", name: "Chips", stock: 6, salesHistory: [3,4,3,5,4] },
      { key: "juice", name: "Juice", stock: 7, salesHistory: [2,2,3,2,3] },
      { key: "soft-drinks", name: "Soft Drinks", stock: 9, salesHistory: [4,5,4,6,5] },
      { key: "canned-food", name: "Canned Food", stock: 4, salesHistory: [1,1,2,1,2] },
      { key: "rice", name: "Rice", stock: 7, salesHistory: [2,3,2,3,2] },
      { key: "salt", name: "Salt", stock: 10, salesHistory: [1,1,1,2,1] }
    ]);
    console.log("✅ Inventory initialized");
  }

  if ((await Franchise.countDocuments()) === 0) {
    await Franchise.insertMany([
      {
        name: "RetailMart - Andheri West", address: "Andheri West, Mumbai",
        lat: 19.1360, lng: 72.8296,
        inventory: { chocolates: 10, biscuits: 5, chips: 8, juice: 3, "soft-drinks": 12 }
      },
      {
        name: "RetailMart - Bandra", address: "Bandra, Mumbai",
        lat: 19.0596, lng: 72.8295,
        inventory: { chocolates: 0, biscuits: 15, chips: 0, juice: 8, "soft-drinks": 6 }
      },
      {
        name: "RetailMart - Powai", address: "Powai, Mumbai",
        lat: 19.1176, lng: 72.9060,
        inventory: { chocolates: 7, biscuits: 0, chips: 5, juice: 0, "soft-drinks": 9 }
      },
      {
        name: "RetailMart - Thane", address: "Thane, Maharashtra",
        lat: 19.2183, lng: 72.9781,
        inventory: { chocolates: 4, biscuits: 8, chips: 6, juice: 5, "soft-drinks": 3 }
      },
      {
        name: "RetailMart - Pune", address: "Pune, Maharashtra",
        lat: 18.5204, lng: 73.8567,
        inventory: { chocolates: 9, biscuits: 6, chips: 4, juice: 7, "soft-drinks": 8 }
      }
    ]);
    console.log("✅ Franchise stores seeded");
  }
}
init();

/* =========================
   JWT AUTH MIDDLEWARE
========================= */
function auth(role) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) return res.status(401).json({ message: "No token provided" });

    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7) : authHeader;

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (role && decoded.role !== role) {
        return res.status(403).json({ message: "Forbidden" });
      }
      req.user = decoded;
      next();
    } catch (err) {
      SecurityLog.create({
        type: "auth_failure", ip: req.ip, path: req.path,
        message: `Invalid token: ${err.message}`
      }).catch(() => {});
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };
}

/* =========================
   INPUT VALIDATION
========================= */
function validateInput(str, maxLen = 200) {
  if (!str) return false;
  if (str.length > maxLen) return false;
  const dangerous = ["<script", "javascript:", "$where", "DROP TABLE", "eval("];
  return !dangerous.some(p => str.toLowerCase().includes(p.toLowerCase()));
}

/* =========================
   SIGNUP
========================= */
app.post("/signup", signupLimiter, async (req, res) => {
  try {
    const { fname, lname, email, password } = req.body;
    if (!fname || !lname || !email || !password) {
      return res.status(400).json({ message: "All fields are required" });
    }
    if (!validateInput(fname, 50) || !validateInput(lname, 50)) {
      return res.status(400).json({ message: "Invalid name" });
    }
    if (password.length < 6) {
      return res.status(400).json({ message: "Password must be at least 6 characters" });
    }
    if (await User.findOne({ email: email.toLowerCase() })) {
      return res.status(400).json({ message: "User already exists" });
    }
    const hashedPassword = await bcrypt.hash(password, 12);
    await User.create({ fname, lname, email: email.toLowerCase(), password: hashedPassword });
    res.json({ message: "Account created successfully" });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   LOGIN
========================= */
app.post("/login", loginLimiter, async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ message: "Username and password required" });
    }
    const user = await User.findOne({ email: username.toLowerCase() });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });

    if (user.lockUntil && user.lockUntil > Date.now()) {
      const minutesLeft = Math.ceil((user.lockUntil - Date.now()) / 60000);
      return res.status(423).json({ message: `Account locked. Try again in ${minutesLeft} minutes` });
    }

    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      user.loginAttempts += 1;
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
        user.loginAttempts = 0;
        await SecurityLog.create({
          type: "account_locked", ip: req.ip, path: "/login",
          message: `Account ${username} locked after 5 failed attempts`
        });
      }
      await user.save();
      return res.status(401).json({ message: "Invalid credentials" });
    }

    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();

    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );
    res.json({ token, role: user.role });
  } catch (err) {
    res.status(500).json({ message: "Server error" });
  }
});

/* =========================
   LOGOUT
========================= */
app.post("/logout", (req, res) => res.json({ message: "Logged out successfully" }));

/* =========================
   MONITORING AGENT
========================= */
setInterval(async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      if (item.stock <= 3 && item.stock > 0) {
        await Log.create({
          type: "monitoring", item: item.name, stock: item.stock,
          message: `⚠️ Low stock alert: ${item.name} has only ${item.stock} left`,
          time: new Date().toLocaleString()
        });
      } else if (item.stock === 0) {
        await Log.create({
          type: "monitoring", item: item.name, stock: 0,
          message: `🚨 OUT OF STOCK: ${item.name}`,
          time: new Date().toLocaleString()
        });
      }
    }
  } catch (err) { console.error("Monitoring agent error:", err.message); }
}, 10000);

/* =========================
   FORECASTING AGENT
========================= */
setInterval(async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      const history = item.salesHistory || [];
      if (history.length < 3) continue;
      const recentSales = history.slice(-5);
      const avgDailySales = recentSales.reduce((a, b) => a + b, 0) / recentSales.length;
      const daysUntilEmpty = avgDailySales > 0 ? Math.floor(item.stock / avgDailySales) : 999;
      if (daysUntilEmpty <= 3) {
        const reorderQty = Math.ceil(avgDailySales * 7);
        await Item.updateOne({ key: item.key }, { $inc: { stock: reorderQty } });
        await Log.create({
          type: "forecasting", item: item.name, stock: reorderQty,
          message: `🤖 Auto-reordered ${reorderQty} units of ${item.name} (${daysUntilEmpty} days until empty, avg: ${avgDailySales.toFixed(1)}/day)`,
          time: new Date().toLocaleString()
        });
      }
    }
  } catch (err) { console.error("Forecasting agent error:", err.message); }
}, 15000);

/* =========================
   SHOP & CHECKOUT
========================= */
app.get("/shop-items", auth("customer"), async (req, res) => {
  try {
    const items = await Item.find();
    const view = {};
    items.forEach(i => {
      view[i.key] = {
        name: i.name, stock: i.stock,
        canBuy: i.stock > 0,
        warning: i.stock <= 3 ? i.stock : null
      };
    });
    res.json(view);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/checkout", auth("customer"), async (req, res) => {
  try {
    const cart = req.body.cart;
    if (!cart || typeof cart !== "object") {
      return res.status(400).json({ message: "Invalid cart" });
    }
    const adjusted = {};
    const notices = [];
    for (const key in cart) {
      if (!validateInput(key, 50)) continue;
      const item = await Item.findOne({ key });
      if (!item) continue;
      const qty = Math.max(0, Math.min(parseInt(cart[key]) || 0, 100));
      const allowed = Math.min(qty, item.stock);
      adjusted[key] = allowed;
      if (qty > item.stock) notices.push(`${item.name}: only ${item.stock} available`);
      await Item.updateOne({ key }, {
        $inc: { stock: -allowed },
        $push: { salesHistory: { $each: [allowed], $slice: -30 } }
      });
    }
    await Order.create({ cart: adjusted, time: new Date().toLocaleString() });
    res.json({ message: "Order placed successfully", notices });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   ADMIN ROUTES
========================= */
app.post("/admin/add-item", auth("admin"), async (req, res) => {
  try {
    const { name, stock } = req.body;
    if (!name || !validateInput(name, 100)) {
      return res.status(400).json({ message: "Invalid item name" });
    }
    const stockNum = parseInt(stock);
    if (isNaN(stockNum) || stockNum < 0 || stockNum > 99999) {
      return res.status(400).json({ message: "Invalid stock value" });
    }
    const key = name.toLowerCase().replace(/\s+/g, "-");
    if (await Item.findOne({ key })) {
      return res.status(400).json({ message: "Item already exists" });
    }
    await Item.create({ key, name, stock: stockNum, salesHistory: [] });
    res.json({ message: "Item added successfully" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/update-stock", auth("admin"), async (req, res) => {
  try {
    const { key, stock } = req.body;
    if (!key || !validateInput(key, 50)) {
      return res.status(400).json({ message: "Invalid key" });
    }
    const stockNum = parseInt(stock);
    if (isNaN(stockNum) || stockNum < 0 || stockNum > 99999) {
      return res.status(400).json({ message: "Invalid stock value" });
    }
    await Item.updateOne({ key }, { $set: { stock: stockNum } });
    res.json({ message: `Stock updated to ${stockNum}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.delete("/admin/delete-item/:key", auth("admin"), async (req, res) => {
  try {
    const key = req.params.key;
    if (!validateInput(key, 50)) {
      return res.status(400).json({ message: "Invalid key" });
    }
    await Item.deleteOne({ key });
    res.json({ message: "Item deleted" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin-data", auth("admin"), async (req, res) => {
  try {
    const inventory = await Item.find();
    const monitoring = await Log.find({ type: "monitoring" }).sort({ _id: -1 }).limit(20);
    const forecasting = await Log.find({ type: "forecasting" }).sort({ _id: -1 }).limit(20);
    res.json({ inventory, monitoring, forecasting });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/reset-logs", auth("admin"), async (req, res) => {
  try {
    await Log.deleteMany({});
    const defaults = {
      chocolates: 5, biscuits: 8, chips: 6, juice: 7,
      "soft-drinks": 9, "canned-food": 4, rice: 7, salt: 10
    };
    for (const key in defaults) {
      await Item.updateOne({ key }, { $set: { stock: defaults[key], salesHistory: [] } });
    }
    res.json({ message: "Reset successful" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/security-logs", auth("admin"), async (req, res) => {
  try {
    const logs = await SecurityLog.find().sort({ time: -1 }).limit(50);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   PLANOGRAM ROUTES
========================= */
app.get("/admin/planogram", auth("admin"), (req, res) => {
  try { res.json(getPlanogram()); }
  catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/planogram", auth("admin"), (req, res) => {
  try {
    const { shelfId, slotMapping } = req.body;
    if (!shelfId || !slotMapping) {
      return res.status(400).json({ message: "shelfId and slotMapping required" });
    }
    updatePlanogram(shelfId, slotMapping);
    res.json({ message: `Planogram updated for ${shelfId}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   SHELF SCAN — YOLO
========================= */
app.post("/admin/scan-shelf", auth("admin"), upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No image uploaded" });
    const imagePath = `/uploads/${req.file.filename}`;
    const totalSlots = parseInt(req.body.total_slots) || 8;
    const shelfId = req.body.shelf_id || "SHELF_001";

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
    } catch (mapErr) {
      console.log("Planogram mapping note:", mapErr.message);
    }

    await ShelfScan.create({
      shelf_id: shelfId, imagePath,
      total_slots: mlData.total_slots,
      occupied_slots: mlData.occupied_slots,
      empty_slots: mlData.empty_slots,
      occupied_slot_numbers: mlData.occupied_slot_numbers,
      empty_slot_numbers: mlData.empty_slot_numbers,
      present_products: presentProducts,
      missing_products: missingProducts,
      detection_details: mlData.detection_details || [],
      stock_counts: mlData.stock_counts || {},
      fill_percentage: mlData.fill_percentage || 0,
      detectedAt: new Date().toLocaleString()
    });

    if (mlData.low_stock_alert) {
      await Log.create({
        type: "monitoring", item: "Shelf Scan", stock: mlData.occupied_slots,
        message: `🚨 Low stock on ${shelfId}: ${mlData.occupied_slots}/${mlData.total_slots} slots occupied`,
        time: new Date().toLocaleString()
      });
    }

    res.json({
      message: "Shelf scanned successfully",
      imagePath, shelf_id: shelfId,
      total_slots: mlData.total_slots,
      occupied_slots: mlData.occupied_slots,
      empty_slots: mlData.empty_slots,
      occupied_slot_numbers: mlData.occupied_slot_numbers,
      empty_slot_numbers: mlData.empty_slot_numbers,
      present_products: presentProducts,
      missing_products: missingProducts,
      detection_details: mlData.detection_details,
      stock_counts: mlData.stock_counts,
      fill_percentage: mlData.fill_percentage,
      low_stock_alert: mlData.low_stock_alert,
      total_detections: mlData.total_detections
    });
  } catch (err) {
    console.error("Scan error:", err.message);
    res.status(500).json({ message: err.message });
  }
});

app.get("/admin/shelf-scans", auth("admin"), async (req, res) => {
  try {
    const scans = await ShelfScan.find().sort({ _id: -1 }).limit(10);
    res.json(scans);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   NEARBY FRANCHISE LOCATOR
========================= */
function calculateDistance(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a =
    Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng/2) * Math.sin(dLng/2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

app.get("/nearby-franchises", auth("customer"), async (req, res) => {
  try {
    const { product, lat, lng } = req.query;
    if (!product || !lat || !lng) {
      return res.status(400).json({ message: "product, lat, lng required" });
    }
    if (!validateInput(product, 50)) {
      return res.status(400).json({ message: "Invalid product" });
    }
    const franchises = await Franchise.find();
    const results = franchises
      .filter(f => f.inventory[product] && f.inventory[product] > 0)
      .map(f => ({
        name: f.name, address: f.address,
        stock: f.inventory[product],
        distance: calculateDistance(parseFloat(lat), parseFloat(lng), f.lat, f.lng).toFixed(2),
        lat: f.lat, lng: f.lng
      }))
      .sort((a, b) => a.distance - b.distance);
    res.json(results);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/franchises", auth("admin"), async (req, res) => {
  try {
    const franchises = await Franchise.find();
    res.json(franchises);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   GLOBAL ERROR HANDLER
========================= */
app.use((err, req, res, next) => {
  console.error("Error:", err.message);
  if (err.message.includes("CORS") || err.message.includes("rate limit")) {
    SecurityLog.create({
      type: "security_error", ip: req.ip,
      path: req.path, message: err.message
    }).catch(() => {});
  }
  res.status(err.status || 500).json({
    message: err.message || "Internal server error"
  });
});

/* =========================
   404 HANDLER
========================= */
app.use((req, res) => {
  res.status(404).json({ message: "Route not found" });
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
  console.log(`🔒 Security layer active`);
});