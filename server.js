/* =========================================
   SHELFSENSE AI — Multi-Agent System
   server.js — Main Backend
   10 Intelligent Agents + Full Security
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
   EMAIL TRANSPORTER
========================= */
const emailTransporter = nodemailer.createTransport({
  service: "gmail",
  auth: {
    user: process.env.ALERT_EMAIL,
    pass: process.env.ALERT_EMAIL_PASSWORD
  }
});

async function sendAlert(subject, message, isUrgent = false) {
  try {
    await emailTransporter.sendMail({
      from: `"ShelfSense AI 🤖" <${process.env.ALERT_EMAIL}>`,
      to: process.env.ADMIN_ALERT_EMAIL,
      subject: `${isUrgent ? "🚨 URGENT: " : "⚠️ "}${subject}`,
      html: `
        <div style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto">
          <div style="background:${isUrgent ? '#dc2626' : '#6366f1'};padding:20px;border-radius:10px 10px 0 0">
            <h1 style="color:white;margin:0;font-size:1.4rem">
              ${isUrgent ? '🚨' : '⚠️'} ShelfSense AI Alert
            </h1>
          </div>
          <div style="background:#f8fafc;padding:24px;border-radius:0 0 10px 10px;border:1px solid #e2e8f0">
            <p style="font-size:1rem;color:#1e293b;line-height:1.6">${message}</p>
            <hr style="border:1px solid #e2e8f0;margin:16px 0">
            <p style="font-size:0.8rem;color:#94a3b8">
              This is an automated alert from ShelfSense AI.<br>
              Time: ${new Date().toLocaleString()}
            </p>
          </div>
        </div>
      `
    });
    console.log(`📧 Alert email sent: ${subject}`);
  } catch (err) {
    console.error("Email error:", err.message);
  }
}

/* =========================
   SECURITY MIDDLEWARE
========================= */
app.use(helmet({ contentSecurityPolicy: false, crossOriginEmbedderPolicy: false }));

const allowedOrigins = [
  "http://localhost:3000",
  "http://127.0.0.1:3000",
  process.env.FRONTEND_URL
].filter(Boolean);

app.use(cors({
  origin: function(origin, callback) {
    if (!origin || allowedOrigins.includes(origin)) callback(null, true);
    else callback(new Error("Not allowed by CORS"));
  },
  methods: ["GET", "POST", "PUT", "DELETE"],
  allowedHeaders: ["Content-Type", "Authorization"],
  credentials: true
}));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, max: 5,
  message: { message: "Too many login attempts" },
  standardHeaders: true, legacyHeaders: false
});

const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, max: 3,
  message: { message: "Too many signup attempts" },
  standardHeaders: true, legacyHeaders: false
});

app.use(express.json({ limit: "10kb" }));
app.use(express.urlencoded({ extended: true, limit: "10kb" }));
app.use(mongoSanitize());

app.use((req, res, next) => {
  const ip = req.ip || req.connection.remoteAddress;
  console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} — IP: ${ip}`);
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
  else cb(new Error("Only JPG, PNG and WEBP images are allowed"), false);
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
  userId: { type: mongoose.Schema.Types.ObjectId, ref: "User" },
  itemKey: String,
  rating: { type: Number, min: 1, max: 5 },
  createdAt: { type: Date, default: Date.now }
});

const StoreSettingsSchema = new mongoose.Schema({
  openingTime: { type: String, default: "09:00" },
  closingTime: { type: String, default: "22:00" },
  storeName: { type: String, default: "My Store" },
  alertEmail: { type: String, default: "" },
  weatherCity: { type: String, default: "Mumbai" },
  currency: { type: String, default: "INR" }
});

const PurchaseOrderSchema = new mongoose.Schema({
  itemKey: String,
  itemName: String,
  quantity: Number,
  supplier: String,
  status: { type: String, default: "pending", enum: ["pending", "sent", "received"] },
  createdAt: { type: Date, default: Date.now }
});

const AgentLogSchema = new mongoose.Schema({
  agent: String,
  action: String,
  details: Object,
  severity: { type: String, default: "info" },
  createdAt: { type: Date, default: Date.now }
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
const Rating = mongoose.model("Rating", RatingSchema);
const StoreSettings = mongoose.model("StoreSettings", StoreSettingsSchema);
const PurchaseOrder = mongoose.model("PurchaseOrder", PurchaseOrderSchema);
const AgentLog = mongoose.model("AgentLog", AgentLogSchema);

/* =========================
   HELPER FUNCTIONS
========================= */
function validateInput(str, maxLen = 200) {
  if (!str) return false;
  if (str.length > maxLen) return false;
  const dangerous = ["<script", "javascript:", "$where", "DROP TABLE", "eval("];
  return !dangerous.some(p => str.toLowerCase().includes(p.toLowerCase()));
}

function isWithinShopHours(openingTime, closingTime) {
  const now = new Date();
  const currentHour = now.getHours();
  const currentMin = now.getMinutes();
  const current = currentHour * 60 + currentMin;
  const [openH, openM] = openingTime.split(":").map(Number);
  const [closeH, closeM] = closingTime.split(":").map(Number);
  const open = openH * 60 + openM;
  const close = closeH * 60 + closeM;
  return current >= open && current <= close;
}

async function logAgent(agent, action, details = {}, severity = "info") {
  await AgentLog.create({ agent, action, details, severity });
  await Log.create({
    type: "agent",
    agent,
    item: details.item || agent,
    stock: details.stock || 0,
    message: action,
    severity,
    time: new Date().toLocaleString()
  });
}

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
      { key: "chocolates", name: "Chocolates", stock: 5, salesHistory: [2,3,2,4,3], price: 149, category: "snacks", supplier: "Nestle", minStockLevel: 3 },
      { key: "biscuits", name: "Biscuits", stock: 8, salesHistory: [1,2,3,2,1], price: 49, category: "snacks", supplier: "Britannia", minStockLevel: 5 },
      { key: "chips", name: "Chips", stock: 6, salesHistory: [3,4,3,5,4], price: 29, category: "snacks", supplier: "Lays", minStockLevel: 4 },
      { key: "juice", name: "Juice", stock: 7, salesHistory: [2,2,3,2,3], price: 99, category: "beverages", supplier: "Tropicana", minStockLevel: 4 },
      { key: "soft-drinks", name: "Soft Drinks", stock: 9, salesHistory: [4,5,4,6,5], price: 59, category: "beverages", supplier: "Coca-Cola", minStockLevel: 5 },
      { key: "canned-food", name: "Canned Food", stock: 4, salesHistory: [1,1,2,1,2], price: 199, category: "food", supplier: "Generic", minStockLevel: 3 },
      { key: "rice", name: "Rice", stock: 7, salesHistory: [2,3,2,3,2], price: 89, category: "staples", supplier: "Local", minStockLevel: 4 },
      { key: "salt", name: "Salt", stock: 10, salesHistory: [1,1,1,2,1], price: 25, category: "staples", supplier: "Tata", minStockLevel: 5 }
    ]);
    console.log("✅ Inventory initialized");
  }

  if ((await StoreSettings.countDocuments()) === 0) {
    await StoreSettings.create({
      openingTime: "09:00",
      closingTime: "22:00",
      storeName: "ShelfSense Store",
      alertEmail: process.env.ADMIN_ALERT_EMAIL,
      weatherCity: "Mumbai"
    });
    console.log("✅ Store settings initialized");
  }

  if ((await Franchise.countDocuments()) === 0) {
    await Franchise.insertMany([
      { name: "ShelfSense - Andheri West", address: "Andheri West, Mumbai", lat: 19.1360, lng: 72.8296, inventory: { chocolates: 10, biscuits: 5, chips: 8, juice: 3, "soft-drinks": 12 } },
      { name: "ShelfSense - Bandra", address: "Bandra, Mumbai", lat: 19.0596, lng: 72.8295, inventory: { chocolates: 0, biscuits: 15, chips: 0, juice: 8, "soft-drinks": 6 } },
      { name: "ShelfSense - Powai", address: "Powai, Mumbai", lat: 19.1176, lng: 72.9060, inventory: { chocolates: 7, biscuits: 0, chips: 5, juice: 0, "soft-drinks": 9 } },
      { name: "ShelfSense - Thane", address: "Thane, Maharashtra", lat: 19.2183, lng: 72.9781, inventory: { chocolates: 4, biscuits: 8, chips: 6, juice: 5, "soft-drinks": 3 } },
      { name: "ShelfSense - Pune", address: "Pune, Maharashtra", lat: 18.5204, lng: 73.8567, inventory: { chocolates: 9, biscuits: 6, chips: 4, juice: 7, "soft-drinks": 8 } }
    ]);
    console.log("✅ Franchise stores seeded");
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
      if (role && decoded.role !== role) return res.status(403).json({ message: "Forbidden" });
      req.user = decoded;
      next();
    } catch (err) {
      SecurityLog.create({ type: "auth_failure", ip: req.ip, path: req.path, message: `Invalid token: ${err.message}` }).catch(() => {});
      return res.status(401).json({ message: "Invalid or expired token" });
    }
  };
}

/* =========================================
   🤖 ALL 10 AI AGENTS
========================================= */

/* =========================
   AGENT 1 — MONITORING AGENT
   Checks stock every 30 seconds
   Sends alerts for low/out of stock
========================= */
cron.schedule("*/30 * * * * *", async () => {
  try {
    const items = await Item.find();
    const settings = await StoreSettings.findOne();

    for (const item of items) {
      if (item.stock === 0) {
        await logAgent("Monitoring Agent", `🚨 OUT OF STOCK: ${item.name}`, { item: item.name, stock: 0 }, "critical");
        await sendAlert(
          `OUT OF STOCK: ${item.name}`,
          `<strong>${item.name}</strong> is completely out of stock!<br><br>Please restock immediately to avoid losing sales.`,
          true
        );
      } else if (item.stock <= item.minStockLevel) {
        await logAgent("Monitoring Agent", `⚠️ Low stock: ${item.name} has only ${item.stock} units left`, { item: item.name, stock: item.stock }, "warning");
      }
    }
  } catch (err) { console.error("Monitoring Agent error:", err.message); }
});

/* =========================
   AGENT 2 — FORECASTING AGENT
   Enhanced with exponential
   smoothing + seasonality
========================= */
cron.schedule("0 */15 * * * *", async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      const history = item.salesHistory || [];
      if (history.length < 3) continue;

      // Exponential smoothing (alpha = 0.3)
      const alpha = 0.3;
      let smoothed = history[0];
      for (let i = 1; i < history.length; i++) {
        smoothed = alpha * history[i] + (1 - alpha) * smoothed;
      }

      // Seasonality — weekend boost
      const dayOfWeek = new Date().getDay();
      const isWeekend = dayOfWeek === 0 || dayOfWeek === 6;
      const seasonalMultiplier = isWeekend ? 1.3 : 1.0;
      const projectedDailySales = smoothed * seasonalMultiplier;

      const daysUntilEmpty = projectedDailySales > 0
        ? Math.floor(item.stock / projectedDailySales)
        : 999;

      if (daysUntilEmpty <= 3 && item.stock > 0) {
        const reorderQty = Math.ceil(projectedDailySales * 7);
        await Item.updateOne({ key: item.key }, { $inc: { stock: reorderQty } });
        await logAgent(
          "Forecasting Agent",
          `🤖 Auto-reordered ${reorderQty} units of ${item.name} (${daysUntilEmpty} days until empty, projected: ${projectedDailySales.toFixed(1)}/day${isWeekend ? ' — weekend boost applied' : ''})`,
          { item: item.name, stock: reorderQty },
          "info"
        );
      }
    }
  } catch (err) { console.error("Forecasting Agent error:", err.message); }
});

/* =========================
   AGENT 3 — ANOMALY DETECTION
   Time-aware burglary/theft
   detection using z-score
========================= */
cron.schedule("*/45 * * * * *", async () => {
  try {
    const items = await Item.find();
    const settings = await StoreSettings.findOne();
    const withinHours = settings ? isWithinShopHours(settings.openingTime, settings.closingTime) : true;

    for (const item of items) {
      const history = item.salesHistory || [];
      if (history.length < 5) continue;

      // Calculate mean and std deviation
      const mean = history.reduce((a, b) => a + b, 0) / history.length;
      const variance = history.reduce((a, b) => a + Math.pow(b - mean, 2), 0) / history.length;
      const std = Math.sqrt(variance);

      // Get recent sales (last entry)
      const recentDrop = history[history.length - 1];
      const zScore = std > 0 ? (recentDrop - mean) / std : 0;

      // Anomaly if z-score > 2.5 (significant drop)
      if (zScore > 2.5) {
        if (!withinHours) {
          // OUTSIDE shop hours — likely theft!
          await logAgent(
            "Anomaly Detection Agent",
            `🚨 POSSIBLE THEFT DETECTED: ${item.name} — Unusual stock drop of ${recentDrop} units OUTSIDE shop hours (${settings?.openingTime} - ${settings?.closingTime})`,
            { item: item.name, stock: recentDrop, zScore: zScore.toFixed(2) },
            "critical"
          );
          await sendAlert(
            `POSSIBLE THEFT: ${item.name}`,
            `🚨 <strong>URGENT SECURITY ALERT</strong><br><br>
            An unusual stock drop of <strong>${recentDrop} units</strong> of <strong>${item.name}</strong> was detected <strong>outside shop hours</strong>.<br><br>
            <strong>Shop Hours:</strong> ${settings?.openingTime} - ${settings?.closingTime}<br>
            <strong>Detection Time:</strong> ${new Date().toLocaleString()}<br>
            <strong>Anomaly Score:</strong> ${zScore.toFixed(2)} (threshold: 2.5)<br><br>
            Please check your security cameras immediately!`,
            true
          );
        } else {
          // Within hours — unusual but not theft
          await logAgent(
            "Anomaly Detection Agent",
            `⚠️ Unusual sales spike detected for ${item.name}: ${recentDrop} units sold (${zScore.toFixed(2)} std devs above normal)`,
            { item: item.name, stock: recentDrop, zScore: zScore.toFixed(2) },
            "warning"
          );
        }
      }
    }
  } catch (err) { console.error("Anomaly Detection Agent error:", err.message); }
});

/* =========================
   AGENT 4 — DYNAMIC PRICING
   Adjusts prices based on
   stock level + demand velocity
========================= */
cron.schedule("0 0 * * * *", async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      const history = item.salesHistory || [];
      if (history.length < 3) continue;

      const recentSales = history.slice(-5);
      const avgSales = recentSales.reduce((a, b) => a + b, 0) / recentSales.length;
      const basePrice = item.price;
      let newPrice = basePrice;
      let reason = "";

      // High demand + low stock = increase price slightly
      if (avgSales > 3 && item.stock <= item.minStockLevel * 2) {
        newPrice = Math.round(basePrice * 1.1);
        reason = "High demand + low stock";
      }
      // Low demand + high stock = decrease price to boost sales
      else if (avgSales < 1 && item.stock > 20) {
        newPrice = Math.round(basePrice * 0.9);
        reason = "Low demand + excess stock";
      }

      if (newPrice !== basePrice) {
        await Item.updateOne({ key: item.key }, { $set: { price: newPrice } });
        await logAgent(
          "Dynamic Pricing Agent",
          `💰 Price adjusted for ${item.name}: ₹${basePrice} → ₹${newPrice} (${reason})`,
          { item: item.name, oldPrice: basePrice, newPrice, reason },
          "info"
        );
      }
    }
  } catch (err) { console.error("Dynamic Pricing Agent error:", err.message); }
});

/* =========================
   AGENT 5 — COMPETITOR ANALYSIS
   Compares prices with market
   averages and suggests changes
========================= */
const MARKET_PRICES = {
  "chocolates": 159, "biscuits": 55, "chips": 35,
  "juice": 110, "soft-drinks": 65, "canned-food": 210,
  "rice": 95, "salt": 28
};

cron.schedule("0 0 9 * * *", async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      const marketPrice = MARKET_PRICES[item.key];
      if (!marketPrice) continue;

      const priceDiff = ((item.price - marketPrice) / marketPrice) * 100;

      if (priceDiff > 15) {
        await logAgent(
          "Competitor Analysis Agent",
          `🏆 ${item.name} is priced ${priceDiff.toFixed(1)}% ABOVE market (₹${item.price} vs market ₹${marketPrice}). Consider reducing price to stay competitive.`,
          { item: item.name, ourPrice: item.price, marketPrice, difference: priceDiff.toFixed(1) },
          "warning"
        );
      } else if (priceDiff < -15) {
        await logAgent(
          "Competitor Analysis Agent",
          `🏆 ${item.name} is priced ${Math.abs(priceDiff).toFixed(1)}% BELOW market (₹${item.price} vs market ₹${marketPrice}). You could increase price for better margins.`,
          { item: item.name, ourPrice: item.price, marketPrice, difference: priceDiff.toFixed(1) },
          "info"
        );
      }
    }
  } catch (err) { console.error("Competitor Analysis Agent error:", err.message); }
});

/* =========================
   AGENT 6 — SUPPLIER/REORDER AGENT
   Auto-generates purchase orders
   when stock falls below minimum
========================= */
cron.schedule("0 0 */2 * * *", async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      if (item.stock <= item.minStockLevel) {
        // Check if order already pending
        const existingOrder = await PurchaseOrder.findOne({
          itemKey: item.key,
          status: "pending"
        });

        if (!existingOrder) {
          const orderQty = item.minStockLevel * 5;
          await PurchaseOrder.create({
            itemKey: item.key,
            itemName: item.name,
            quantity: orderQty,
            supplier: item.supplier || "Default Supplier",
            status: "pending"
          });

          await logAgent(
            "Supplier Agent",
            `🔄 Purchase order created: ${orderQty} units of ${item.name} from ${item.supplier || "Default Supplier"}`,
            { item: item.name, quantity: orderQty, supplier: item.supplier },
            "info"
          );

          await sendAlert(
            `Purchase Order Created: ${item.name}`,
            `A purchase order has been automatically generated:<br><br>
            <strong>Item:</strong> ${item.name}<br>
            <strong>Quantity:</strong> ${orderQty} units<br>
            <strong>Supplier:</strong> ${item.supplier || "Default Supplier"}<br>
            <strong>Current Stock:</strong> ${item.stock} units<br>
            <strong>Minimum Level:</strong> ${item.minStockLevel} units`,
            false
          );
        }
      }
    }
  } catch (err) { console.error("Supplier Agent error:", err.message); }
});

/* =========================
   AGENT 7 — CUSTOMER BEHAVIOR
   Association rule mining —
   finds products bought together
========================= */
cron.schedule("0 0 1 * * *", async () => {
  try {
    const orders = await Order.find().limit(100);
    if (orders.length < 5) return;

    // Build co-occurrence matrix
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

    // Find strong associations (bought together 2+ times)
    const associations = Object.entries(coOccurrence)
      .filter(([, count]) => count >= 2)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 5);

    if (associations.length > 0) {
      const insights = associations
        .map(([pair, count]) => {
          const [a, b] = pair.split("+");
          return `${a} + ${b} (bought together ${count} times)`;
        })
        .join(", ");

      await logAgent(
        "Customer Behavior Agent",
        `👥 Bundle opportunities detected: ${insights}. Consider creating bundle deals for these products!`,
        { associations: associations.map(([pair, count]) => ({ pair, count })) },
        "info"
      );
    }
  } catch (err) { console.error("Customer Behavior Agent error:", err.message); }
});

/* =========================
   AGENT 8 — WEATHER AGENT
   Adjusts stock recommendations
   based on weather conditions
========================= */
cron.schedule("0 0 8 * * *", async () => {
  try {
    const settings = await StoreSettings.findOne();
    const city = settings?.weatherCity || "Mumbai";

    // Open-Meteo free API — no API key needed!
    const geoRes = await axios.get(
      `https://geocoding-api.open-meteo.com/v1/search?name=${city}&count=1`
    );

    if (!geoRes.data.results?.length) return;

    const { latitude, longitude } = geoRes.data.results[0];

    const weatherRes = await axios.get(
      `https://api.open-meteo.com/v1/forecast?latitude=${latitude}&longitude=${longitude}&current=temperature_2m,weathercode&timezone=auto`
    );

    const temp = weatherRes.data.current.temperature_2m;
    const code = weatherRes.data.current.weathercode;

    let recommendation = "";
    let itemsToBoost = [];

    if (temp > 35) {
      recommendation = "Extremely hot weather! Stock up on cold drinks and ice cream.";
      itemsToBoost = ["soft-drinks", "juice"];
    } else if (temp > 28) {
      recommendation = "Hot weather — increase stock of beverages.";
      itemsToBoost = ["soft-drinks", "juice"];
    } else if (code >= 61 && code <= 67) {
      recommendation = "Rainy weather — stock up on hot beverages and snacks.";
      itemsToBoost = ["biscuits", "chips"];
    } else if (temp < 20) {
      recommendation = "Cool weather — chocolates and warm foods will sell well.";
      itemsToBoost = ["chocolates", "canned-food"];
    }

    if (recommendation) {
      await logAgent(
        "Weather Agent",
        `🌦️ Weather in ${city}: ${temp}°C — ${recommendation}`,
        { city, temperature: temp, weatherCode: code, itemsToBoost },
        "info"
      );
    }
  } catch (err) { console.error("Weather Agent error:", err.message); }
});

/* =========================
   AGENT 9 — EXPIRY AGENT
   Tracks expiry dates and
   auto-discounts near-expiry items
========================= */
cron.schedule("0 0 7 * * *", async () => {
  try {
    const items = await Item.find({ expiryDate: { $ne: null } });
    const today = new Date();

    for (const item of items) {
      if (!item.expiryDate) continue;
      const daysUntilExpiry = Math.ceil(
        (new Date(item.expiryDate) - today) / (1000 * 60 * 60 * 24)
      );

      if (daysUntilExpiry <= 0) {
        await logAgent(
          "Expiry Agent",
          `🗓️ EXPIRED: ${item.name} expired on ${item.expiryDate.toLocaleDateString()}. Remove from shelves immediately!`,
          { item: item.name, expiryDate: item.expiryDate },
          "critical"
        );
        await sendAlert(
          `EXPIRED PRODUCT: ${item.name}`,
          `<strong>${item.name}</strong> has expired!<br><br>
          <strong>Expiry Date:</strong> ${item.expiryDate.toLocaleDateString()}<br>
          Please remove this product from shelves immediately.`,
          true
        );
      } else if (daysUntilExpiry <= 7) {
        // Auto-apply 30% discount for near-expiry items
        const discountPrice = Math.round(item.price * 0.7);
        await Item.updateOne({ key: item.key }, {
          $set: { onSale: true, salePercent: 30, salePrice: discountPrice }
        });
        await logAgent(
          "Expiry Agent",
          `🗓️ Near-expiry discount applied: ${item.name} expires in ${daysUntilExpiry} days — 30% discount applied (₹${item.price} → ₹${discountPrice})`,
          { item: item.name, daysUntilExpiry, discountPrice },
          "warning"
        );
      } else if (daysUntilExpiry <= 30) {
        await logAgent(
          "Expiry Agent",
          `🗓️ Expiry warning: ${item.name} expires in ${daysUntilExpiry} days. Consider discounting soon.`,
          { item: item.name, daysUntilExpiry },
          "info"
        );
      }
    }
  } catch (err) { console.error("Expiry Agent error:", err.message); }
});

/* =========================
   AGENT 10 — ROUTE OPTIMIZATION
   Finds optimal transfer routes
   between franchise stores
========================= */
cron.schedule("0 0 6 * * *", async () => {
  try {
    const items = await Item.find({ stock: 0 });
    if (!items.length) return;

    const franchises = await Franchise.find();

    for (const item of items) {
      // Find nearest franchise with stock
      const sourceFranchises = franchises
        .filter(f => f.inventory[item.key] && f.inventory[item.key] > 5)
        .map(f => ({
          name: f.name,
          address: f.address,
          stock: f.inventory[item.key],
          // Distance from main store (Mumbai center)
          distance: calculateDistance(19.0760, 72.8777, f.lat, f.lng)
        }))
        .sort((a, b) => a.distance - b.distance);

      if (sourceFranchises.length > 0) {
        const nearest = sourceFranchises[0];
        await logAgent(
          "Route Optimization Agent",
          `🗺️ Stock transfer recommended: Get ${item.name} from ${nearest.name} (${nearest.distance.toFixed(1)} km away, has ${nearest.stock} units). This is the nearest franchise with sufficient stock.`,
          { item: item.name, source: nearest.name, distance: nearest.distance.toFixed(1), availableStock: nearest.stock },
          "info"
        );
      }
    }
  } catch (err) { console.error("Route Optimization Agent error:", err.message); }
});

/* =========================
   DISTANCE CALCULATOR
========================= */
function calculateDistance(lat1, lng1, lat2, lng2) {
  const R = 6371;
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLng = (lng2 - lng1) * Math.PI / 180;
  const a = Math.sin(dLat/2) * Math.sin(dLat/2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLng/2) * Math.sin(dLng/2);
  return R * 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1-a));
}

/* =========================================
   API ROUTES
========================================= */

/* =========================
   AUTH ROUTES
========================= */
app.post("/signup", signupLimiter, async (req, res) => {
  try {
    const { fname, lname, email, password } = req.body;
    if (!fname || !lname || !email || !password) return res.status(400).json({ message: "All fields are required" });
    if (!validateInput(fname, 50) || !validateInput(lname, 50)) return res.status(400).json({ message: "Invalid name" });
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
      if (user.loginAttempts >= 5) {
        user.lockUntil = new Date(Date.now() + 30 * 60 * 1000);
        user.loginAttempts = 0;
        await SecurityLog.create({ type: "account_locked", ip: req.ip, path: "/login", message: `Account ${username} locked` });
      }
      await user.save();
      return res.status(401).json({ message: "Invalid credentials" });
    }
    user.loginAttempts = 0;
    user.lockUntil = null;
    await user.save();
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email, fname: user.fname },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );
    res.json({ token, role: user.role, fname: user.fname });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/logout", (req, res) => res.json({ message: "Logged out successfully" }));

/* =========================
   SHOP ROUTES
========================= */
app.get("/shop-items", auth("customer"), async (req, res) => {
  try {
    const items = await Item.find();
    const view = {};
    items.forEach(i => {
      view[i.key] = {
        name: i.name, stock: i.stock,
        price: i.price || 99,
        onSale: i.onSale || false,
        salePercent: i.salePercent || 0,
        salePrice: i.salePrice || i.price || 99,
        canBuy: i.stock > 0,
        warning: i.stock <= 3 ? i.stock : null,
        avgRating: i.avgRating || 0,
        totalRatings: i.totalRatings || 0
      };
    });
    res.json(view);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/checkout", auth("customer"), async (req, res) => {
  try {
    const cart = req.body.cart;
    if (!cart || typeof cart !== "object") return res.status(400).json({ message: "Invalid cart" });
    const adjusted = {}, itemNames = {}, notices = [];
    let totalItems = 0, totalAmount = 0;
    for (const key in cart) {
      if (!validateInput(key, 50)) continue;
      const item = await Item.findOne({ key });
      if (!item) continue;
      const qty = Math.max(0, Math.min(parseInt(cart[key]) || 0, 100));
      const allowed = Math.min(qty, item.stock);
      adjusted[key] = allowed;
      itemNames[key] = item.name;
      totalItems += allowed;
      totalAmount += (item.onSale ? item.salePrice : item.price || 99) * allowed;
      if (qty > item.stock) notices.push(`${item.name}: only ${item.stock} available`);
      await Item.updateOne({ key }, {
        $inc: { stock: -allowed },
        $push: { salesHistory: { $each: [allowed], $slice: -30 } }
      });
    }
    await Order.create({ userId: req.user.id, userEmail: req.user.email, cart: adjusted, itemNames, totalItems, totalAmount, paymentStatus: "paid", time: new Date().toLocaleString() });
    res.json({ message: "Order placed successfully", notices });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/my-orders", auth("customer"), async (req, res) => {
  try {
    const orders = await Order.find({ userId: req.user.id }).sort({ createdAt: -1 }).limit(20);
    res.json(orders);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/rate-product", auth("customer"), async (req, res) => {
  try {
    const { itemKey, rating } = req.body;
    if (!itemKey || !rating || rating < 1 || rating > 5) return res.status(400).json({ message: "Invalid rating" });
    const item = await Item.findOne({ key: itemKey });
    if (!item) return res.status(404).json({ message: "Item not found" });
    const existing = await Rating.findOne({ userId: req.user.id, itemKey });
    if (existing) { existing.rating = rating; await existing.save(); }
    else await Rating.create({ userId: req.user.id, itemKey, rating });
    const allRatings = await Rating.find({ itemKey });
    const avg = allRatings.reduce((a, b) => a + b.rating, 0) / allRatings.length;
    await Item.updateOne({ key: itemKey }, { $set: { avgRating: Math.round(avg * 10) / 10, totalRatings: allRatings.length } });
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
   RAZORPAY ROUTES
========================= */
app.post("/create-payment-order", auth("customer"), async (req, res) => {
  try {
    const { cart } = req.body;
    if (!cart || typeof cart !== "object") return res.status(400).json({ message: "Invalid cart" });
    let totalAmount = 0;
    for (const key in cart) {
      const item = await Item.findOne({ key });
      if (item && cart[key] > 0) {
        totalAmount += (item.onSale ? item.salePrice : item.price || 99) * cart[key];
      }
    }
    if (totalAmount === 0) return res.status(400).json({ message: "Cart is empty" });
    const order = await razorpay.orders.create({
      amount: totalAmount * 100,
      currency: "INR",
      receipt: `order_${Date.now()}`,
      notes: { userId: req.user.id, userEmail: req.user.email }
    });
    res.json({ orderId: order.id, amount: order.amount, currency: order.currency, keyId: process.env.RAZORPAY_KEY_ID });
  } catch (err) {
    console.error("Payment order error:", err.message);
    res.status(500).json({ message: "Failed to create payment order" });
  }
});

app.post("/verify-payment", auth("customer"), async (req, res) => {
  try {
    const { razorpay_order_id, razorpay_payment_id, razorpay_signature, cart } = req.body;
    const body = razorpay_order_id + "|" + razorpay_payment_id;
    const expectedSignature = crypto.createHmac("sha256", process.env.RAZORPAY_KEY_SECRET).update(body.toString()).digest("hex");
    if (expectedSignature !== razorpay_signature) return res.status(400).json({ message: "Payment verification failed" });
    const adjusted = {}, itemNames = {}, notices = [];
    let totalItems = 0, totalAmount = 0;
    for (const key in cart) {
      if (!validateInput(key, 50)) continue;
      const item = await Item.findOne({ key });
      if (!item) continue;
      const qty = Math.max(0, Math.min(parseInt(cart[key]) || 0, 100));
      const allowed = Math.min(qty, item.stock);
      adjusted[key] = allowed;
      itemNames[key] = item.name;
      totalItems += allowed;
      totalAmount += (item.onSale ? item.salePrice : item.price || 99) * allowed;
      if (qty > item.stock) notices.push(`${item.name}: only ${item.stock} available`);
      await Item.updateOne({ key }, { $inc: { stock: -allowed }, $push: { salesHistory: { $each: [allowed], $slice: -30 } } });
    }
    await Order.create({ userId: req.user.id, userEmail: req.user.email, cart: adjusted, itemNames, totalItems, totalAmount, paymentId: razorpay_payment_id, paymentStatus: "paid", time: new Date().toLocaleString() });
    res.json({ message: "Payment successful! Order placed.", paymentId: razorpay_payment_id, notices });
  } catch (err) { res.status(500).json({ message: "Payment verification error" }); }
});

/* =========================
   NEARBY FRANCHISES
========================= */
app.get("/nearby-franchises", auth("customer"), async (req, res) => {
  try {
    const { product, lat, lng } = req.query;
    if (!product || !lat || !lng) return res.status(400).json({ message: "product, lat, lng required" });
    if (!validateInput(product, 50)) return res.status(400).json({ message: "Invalid product" });
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
   ADMIN ROUTES
========================= */
app.get("/admin-data", auth("admin"), async (req, res) => {
  try {
    const inventory = await Item.find();
    const monitoring = await Log.find({ type: "agent" }).sort({ _id: -1 }).limit(50);
    const forecasting = await Log.find({ agent: "Forecasting Agent" }).sort({ _id: -1 }).limit(20);
    res.json({ inventory, monitoring, forecasting });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/add-item", auth("admin"), async (req, res) => {
  try {
    const { name, stock } = req.body;
    if (!name || !validateInput(name, 100)) return res.status(400).json({ message: "Invalid item name" });
    const stockNum = parseInt(stock);
    if (isNaN(stockNum) || stockNum < 0 || stockNum > 99999) return res.status(400).json({ message: "Invalid stock value" });
    const key = name.toLowerCase().replace(/\s+/g, "-");
    if (await Item.findOne({ key })) return res.status(400).json({ message: "Item already exists" });
    await Item.create({ key, name, stock: stockNum, salesHistory: [] });
    res.json({ message: "Item added successfully" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/update-stock", auth("admin"), async (req, res) => {
  try {
    const { key, stock } = req.body;
    if (!key || !validateInput(key, 50)) return res.status(400).json({ message: "Invalid key" });
    const stockNum = parseInt(stock);
    if (isNaN(stockNum) || stockNum < 0 || stockNum > 99999) return res.status(400).json({ message: "Invalid stock value" });
    await Item.updateOne({ key }, { $set: { stock: stockNum } });
    res.json({ message: `Stock updated to ${stockNum}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/update-price", auth("admin"), async (req, res) => {
  try {
    const { key, price } = req.body;
    if (!key) return res.status(400).json({ message: "Invalid key" });
    const priceNum = parseFloat(price);
    if (isNaN(priceNum) || priceNum < 0) return res.status(400).json({ message: "Invalid price" });
    await Item.updateOne({ key }, { $set: { price: priceNum } });
    res.json({ message: `Price updated to ₹${priceNum}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/update-sale", auth("admin"), async (req, res) => {
  try {
    const { key, onSale, salePercent } = req.body;
    if (!key) return res.status(400).json({ message: "Invalid key" });
    const item = await Item.findOne({ key });
    if (!item) return res.status(404).json({ message: "Item not found" });
    const pct = parseFloat(salePercent) || 0;
    const salePrice = onSale ? Math.round(item.price * (1 - pct / 100)) : item.price;
    await Item.updateOne({ key }, { $set: { onSale, salePercent: pct, salePrice } });
    res.json({ message: onSale ? `Sale set: ${pct}% off` : "Sale removed" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.delete("/admin/delete-item/:key", auth("admin"), async (req, res) => {
  try {
    const key = req.params.key;
    if (!validateInput(key, 50)) return res.status(400).json({ message: "Invalid key" });
    await Item.deleteOne({ key });
    res.json({ message: "Item deleted" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/reset-logs", auth("admin"), async (req, res) => {
  try {
    await Log.deleteMany({});
    await AgentLog.deleteMany({});
    const defaults = { chocolates: 5, biscuits: 8, chips: 6, juice: 7, "soft-drinks": 9, "canned-food": 4, rice: 7, salt: 10 };
    for (const key in defaults) {
      await Item.updateOne({ key }, { $set: { stock: defaults[key], salesHistory: [] } });
    }
    res.json({ message: "Reset successful" });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   AGENT LOGS ROUTES
========================= */
app.get("/admin/agent-logs", auth("admin"), async (req, res) => {
  try {
    const { agent, severity } = req.query;
    const filter = {};
    if (agent && agent !== "all") filter.agent = agent;
    if (severity && severity !== "all") filter.severity = severity;
    const logs = await AgentLog.find(filter).sort({ createdAt: -1 }).limit(100);
    res.json(logs);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.get("/admin/purchase-orders", auth("admin"), async (req, res) => {
  try {
    const orders = await PurchaseOrder.find().sort({ createdAt: -1 }).limit(20);
    res.json(orders);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/purchase-orders/:id/status", auth("admin"), async (req, res) => {
  try {
    const { status } = req.body;
    await PurchaseOrder.updateOne({ _id: req.params.id }, { $set: { status } });
    if (status === "received") {
      const order = await PurchaseOrder.findById(req.params.id);
      if (order) {
        await Item.updateOne({ key: order.itemKey }, { $inc: { stock: order.quantity } });
      }
    }
    res.json({ message: `Order status updated to ${status}` });
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

/* =========================
   STORE SETTINGS
========================= */
app.get("/admin/settings", auth("admin"), async (req, res) => {
  try {
    const settings = await StoreSettings.findOne();
    res.json(settings);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
});

app.post("/admin/settings", auth("admin"), async (req, res) => {
  try {
    const { openingTime, closingTime, storeName, alertEmail, weatherCity } = req.body;
    await StoreSettings.updateOne({}, {
      $set: { openingTime, closingTime, storeName, alertEmail, weatherCity }
    });
    res.json({ message: "Settings saved successfully!" });
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
    if (!shelfId || !slotMapping) return res.status(400).json({ message: "shelfId and slotMapping required" });
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
    } catch (mapErr) { console.log("Planogram mapping note:", mapErr.message); }

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

app.get("/admin/franchises", auth("admin"), async (req, res) => {
  try {
    const franchises = await Franchise.find();
    res.json(franchises);
  } catch (err) { res.status(500).json({ message: "Server error" }); }
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
  console.log(`💳 Razorpay payment gateway active`);
  console.log(`📧 Email alerts active`);
});