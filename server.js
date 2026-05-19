/* =========================================
   RETAIL MART AGENTIC AI SYSTEM
   server.js — Main Backend
   Fixes: .env, bcrypt passwords, JWT tokens
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

const mapSlotsToProducts = require("./slotProductMapper");

const app = express();
app.use(express.json());
app.use(express.static("public"));
app.use("/uploads", express.static("uploads"));

/* =========================
   IMAGE UPLOAD CONFIG
========================= */
if (!fs.existsSync("uploads")) {
  fs.mkdirSync("uploads");
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, "uploads"),
  filename: (req, file, cb) =>
    cb(null, Date.now() + path.extname(file.originalname))
});

const upload = multer({ storage });

/* =========================
   MONGODB CONNECTION
   Now uses .env file — no hardcoding!
========================= */
mongoose
  .connect(process.env.MONGODB_URI)
  .then(() => console.log("✅ MongoDB connected"))
  .catch(err => console.error("❌ Mongo error", err));

/* =========================
   SCHEMAS
========================= */
const UserSchema = new mongoose.Schema({
  role: { type: String, default: "customer" },
  fname: String,
  lname: String,
  email: { type: String, unique: true },
  password: String
});

const ItemSchema = new mongoose.Schema({
  key: String,
  name: String,
  stock: Number,
  salesHistory: { type: [Number], default: [] }
});

const OrderSchema = new mongoose.Schema({
  cart: Object,
  time: String
});

const LogSchema = new mongoose.Schema({
  type: String,
  item: String,
  stock: Number,
  message: String,
  time: String
});

const ShelfScanSchema = new mongoose.Schema({
  shelf_id: String,
  imagePath: String,
  total_slots: Number,
  occupied_slots: Number,
  empty_slots: Number,
  occupied_slot_numbers: Array,
  empty_slot_numbers: Array,
  present_products: Array,
  missing_products: Array,
  detectedAt: String
});

/* =========================
   MODELS
========================= */
const User = mongoose.model("User", UserSchema);
const Item = mongoose.model("Item", ItemSchema);
const Order = mongoose.model("Order", OrderSchema);
const Log = mongoose.model("Log", LogSchema);
const ShelfScan = mongoose.model("ShelfScan", ShelfScanSchema);

/* =========================
   INIT — Create admin + items
========================= */
async function init() {
  // Create default admin if not exists
  if (!(await User.findOne({ role: "admin" }))) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
    await User.create({
      role: "admin",
      fname: "Store",
      lname: "Admin",
      email: "admin",
      password: hashedPassword
    });
    console.log("✅ Admin user created");
  }

  // Create default inventory if empty
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
}
init();

/* =========================
   JWT AUTH MIDDLEWARE
   Replaces the old Date.now() token system
========================= */
function auth(role) {
  return (req, res, next) => {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ message: "No token provided" });
    }

    // Token comes as "Bearer <token>"
    const token = authHeader.startsWith("Bearer ")
      ? authHeader.slice(7)
      : authHeader;

    try {
      const decoded = jwt.verify(token, process.env.JWT_SECRET);
      if (role && decoded.role !== role) {
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
   SIGNUP
========================= */
app.post("/signup", async (req, res) => {
  try {
    const { fname, lname, email, password } = req.body;
    if (await User.findOne({ email })) {
      return res.status(400).json({ message: "User already exists" });
    }
    // Hash password before saving — never store plain text!
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ fname, lname, email, password: hashedPassword });
    res.json({ message: "Account created successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   LOGIN
========================= */
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ email: username });
    if (!user) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Compare entered password with hashed password in database
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) {
      return res.status(401).json({ message: "Invalid credentials" });
    }

    // Create JWT token — expires in 24 hours
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );

    res.json({ token, role: user.role });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   LOGOUT
========================= */
app.post("/logout", (req, res) => {
  // With JWT, logout is handled on the frontend by deleting the token
  res.json({ message: "Logged out successfully" });
});

/* =========================
   MONITORING AGENT
   Checks stock every 10 seconds, logs alerts
========================= */
setInterval(async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      if (item.stock <= 3 && item.stock > 0) {
        await Log.create({
          type: "monitoring",
          item: item.name,
          stock: item.stock,
          message: `⚠️ Low stock alert: ${item.name} has only ${item.stock} left`,
          time: new Date().toLocaleString()
        });
      } else if (item.stock === 0) {
        await Log.create({
          type: "monitoring",
          item: item.name,
          stock: 0,
          message: `🚨 OUT OF STOCK: ${item.name}`,
          time: new Date().toLocaleString()
        });
      }
    }
  } catch (err) {
    console.error("Monitoring agent error:", err.message);
  }
}, 10000);

/* =========================
   FORECASTING AGENT
   Simple moving average prediction
   Triggers reorder when stock will run out
========================= */
setInterval(async () => {
  try {
    const items = await Item.find();
    for (const item of items) {
      const history = item.salesHistory || [];

      // Need at least 3 days of history to forecast
      if (history.length < 3) continue;

      // Calculate average daily sales (moving average)
      const recentSales = history.slice(-5);
      const avgDailySales = recentSales.reduce((a, b) => a + b, 0) / recentSales.length;

      // Forecast: how many days until stock runs out?
      const daysUntilEmpty = avgDailySales > 0
        ? Math.floor(item.stock / avgDailySales)
        : 999;

      // Trigger reorder if stock will run out within 3 days
      if (daysUntilEmpty <= 3) {
        const reorderQty = Math.ceil(avgDailySales * 7); // reorder 7 days worth
        await Item.updateOne({ key: item.key }, { $inc: { stock: reorderQty } });
        await Log.create({
          type: "forecasting",
          item: item.name,
          stock: reorderQty,
          message: `🤖 Auto-reordered ${reorderQty} units of ${item.name} (${daysUntilEmpty} days until empty, avg sales: ${avgDailySales.toFixed(1)}/day)`,
          time: new Date().toLocaleString()
        });
      }
    }
  } catch (err) {
    console.error("Forecasting agent error:", err.message);
  }
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
        name: i.name,
        stock: i.stock,
        canBuy: i.stock > 0,
        warning: i.stock <= 3 ? i.stock : null
      };
    });
    res.json(view);
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.post("/checkout", auth("customer"), async (req, res) => {
  try {
    const cart = req.body.cart;
    const adjusted = {};
    const notices = [];

    for (const key in cart) {
      const item = await Item.findOne({ key });
      if (!item) continue;

      const allowed = Math.min(cart[key], item.stock);
      adjusted[key] = allowed;

      if (cart[key] > item.stock) {
        notices.push(`${item.name}: only ${item.stock} available`);
      }

      // Deduct stock and record sale in history
      await Item.updateOne(
        { key },
        {
          $inc: { stock: -allowed },
          $push: { salesHistory: { $each: [allowed], $slice: -30 } }
        }
      );
    }

    await Order.create({ cart: adjusted, time: new Date().toLocaleString() });
    res.json({ message: "Order placed successfully", notices });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   ADMIN ROUTES
========================= */
app.post("/admin/add-item", auth("admin"), async (req, res) => {
  try {
    const { name, stock } = req.body;
    const key = name.toLowerCase().replace(/\s+/g, "-");
    if (await Item.findOne({ key })) {
      return res.status(400).json({ message: "Item already exists" });
    }
    await Item.create({ key, name, stock, salesHistory: [] });
    res.json({ message: "Item added successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/admin/delete-item/:key", auth("admin"), async (req, res) => {
  try {
    await Item.deleteOne({ key: req.params.key });
    res.json({ message: "Item deleted" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.get("/admin-data", auth("admin"), async (req, res) => {
  try {
    const inventory = await Item.find();
    const monitoring = await Log.find({ type: "monitoring" }).sort({ _id: -1 }).limit(20);
    const forecasting = await Log.find({ type: "forecasting" }).sort({ _id: -1 }).limit(20);
    res.json({ inventory, monitoring, forecasting });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
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
    res.json({ message: "Logs and stocks reset successfully" });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   SHELF SCAN UPLOAD
========================= */
app.post("/admin/scan-shelf", auth("admin"), upload.single("image"), async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ message: "No image uploaded" });
    }
    const imagePath = `/uploads/${req.file.filename}`;
    res.json({
      message: "Image uploaded successfully. YOLO processing coming soon.",
      imagePath
    });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log(`🚀 Server running at http://localhost:${PORT}`);
});