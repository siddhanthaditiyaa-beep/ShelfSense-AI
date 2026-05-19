/* =========================================
   RETAIL MART AGENTIC AI SYSTEM
   server.js — Main Backend
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

const { mapSlotsToProducts, updatePlanogram, getPlanogram } = require("./slotProductMapper");

const app = express();
app.use(express.json());
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

const upload = multer({ storage });

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
  detection_details: Array,
  stock_counts: Object,
  fill_percentage: Number,
  detectedAt: String
});

const FranchiseSchema = new mongoose.Schema({
  name: String,
  address: String,
  lat: Number,
  lng: Number,
  inventory: Object
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

/* =========================
   INIT
========================= */
async function init() {
  if (!(await User.findOne({ role: "admin" }))) {
    const hashedPassword = await bcrypt.hash("admin123", 10);
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
      if (role && decoded.role !== role) return res.status(403).json({ message: "Forbidden" });
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
    if (await User.findOne({ email })) return res.status(400).json({ message: "User already exists" });
    const hashedPassword = await bcrypt.hash(password, 10);
    await User.create({ fname, lname, email, password: hashedPassword });
    res.json({ message: "Account created successfully" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

/* =========================
   LOGIN
========================= */
app.post("/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ email: username });
    if (!user) return res.status(401).json({ message: "Invalid credentials" });
    const passwordMatch = await bcrypt.compare(password, user.password);
    if (!passwordMatch) return res.status(401).json({ message: "Invalid credentials" });
    const token = jwt.sign(
      { id: user._id, role: user.role, email: user.email },
      process.env.JWT_SECRET,
      { expiresIn: "24h" }
    );
    res.json({ token, role: user.role });
  } catch (err) { res.status(500).json({ message: err.message }); }
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
  } catch (err) { res.status(500).json({ message: err.message }); }
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
      if (cart[key] > item.stock) notices.push(`${item.name}: only ${item.stock} available`);
      await Item.updateOne({ key }, {
        $inc: { stock: -allowed },
        $push: { salesHistory: { $each: [allowed], $slice: -30 } }
      });
    }
    await Order.create({ cart: adjusted, time: new Date().toLocaleString() });
    res.json({ message: "Order placed successfully", notices });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

/* =========================
   ADMIN ROUTES
========================= */
app.post("/admin/add-item", auth("admin"), async (req, res) => {
  try {
    const { name, stock } = req.body;
    const key = name.toLowerCase().replace(/\s+/g, "-");
    if (await Item.findOne({ key })) return res.status(400).json({ message: "Item already exists" });
    await Item.create({ key, name, stock, salesHistory: [] });
    res.json({ message: "Item added successfully" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/admin/update-stock", auth("admin"), async (req, res) => {
  try {
    const { key, stock } = req.body;
    if (!key || stock === undefined) return res.status(400).json({ message: "key and stock required" });
    await Item.updateOne({ key }, { $set: { stock: parseInt(stock) } });
    res.json({ message: `Stock updated to ${stock}` });
  } catch (err) {
    res.status(500).json({ message: err.message });
  }
});

app.delete("/admin/delete-item/:key", auth("admin"), async (req, res) => {
  try {
    await Item.deleteOne({ key: req.params.key });
    res.json({ message: "Item deleted" });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get("/admin-data", auth("admin"), async (req, res) => {
  try {
    const inventory = await Item.find();
    const monitoring = await Log.find({ type: "monitoring" }).sort({ _id: -1 }).limit(20);
    const forecasting = await Log.find({ type: "forecasting" }).sort({ _id: -1 }).limit(20);
    res.json({ inventory, monitoring, forecasting });
  } catch (err) { res.status(500).json({ message: err.message }); }
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
  } catch (err) { res.status(500).json({ message: err.message }); }
});

/* =========================
   PLANOGRAM ROUTES
========================= */
app.get("/admin/planogram", auth("admin"), (req, res) => {
  try { res.json(getPlanogram()); }
  catch (err) { res.status(500).json({ message: err.message }); }
});

app.post("/admin/planogram", auth("admin"), (req, res) => {
  try {
    const { shelfId, slotMapping } = req.body;
    if (!shelfId || !slotMapping) return res.status(400).json({ message: "shelfId and slotMapping required" });
    updatePlanogram(shelfId, slotMapping);
    res.json({ message: `Planogram updated for ${shelfId}` });
  } catch (err) { res.status(500).json({ message: err.message }); }
});

/* =========================
   SHELF SCAN — YOLO
   ⭐ KEY FIX: Now correctly passes
   total_slots and shelf_id from
   the admin form to ML service
========================= */
app.post("/admin/scan-shelf", auth("admin"), upload.single("image"), async (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ message: "No image uploaded" });

    const imagePath = `/uploads/${req.file.filename}`;

    // ⭐ Read total_slots and shelf_id from the form data
    const totalSlots = parseInt(req.body.total_slots) || 8;
    const shelfId = req.body.shelf_id || "SHELF_001";

    console.log(`📊 Scanning ${shelfId} with ${totalSlots} slots...`);

    // Send to ML service with correct slot count
    const mlResponse = await fetch("http://127.0.0.1:5001/process-shelf-image", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        imagePath,
        total_slots: totalSlots,
        shelf_id: shelfId
      })
    });

    if (!mlResponse.ok) throw new Error("ML service error");
    const mlData = await mlResponse.json();

    console.log(`✅ ML result: ${mlData.occupied_slots} occupied, ${mlData.empty_slots} empty`);

    // Map slots to products using planogram
    let presentProducts = mlData.present_products || [];
    let missingProducts = mlData.missing_products || [];

    try {
      const mapped = mapSlotsToProducts(
        shelfId,
        mlData.occupied_slot_numbers,
        mlData.empty_slot_numbers
      );
      presentProducts = mapped.present_products;
      missingProducts = mapped.missing_products;
    } catch (mapErr) {
      console.log("Planogram mapping note:", mapErr.message);
    }

    // Save scan to MongoDB
    await ShelfScan.create({
      shelf_id: shelfId,
      imagePath,
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

    // Log alert if low stock
    if (mlData.low_stock_alert) {
      await Log.create({
        type: "monitoring",
        item: "Shelf Scan",
        stock: mlData.occupied_slots,
        message: `🚨 Low stock on ${shelfId}: ${mlData.occupied_slots}/${mlData.total_slots} slots occupied. Missing: ${missingProducts.join(", ")}`,
        time: new Date().toLocaleString()
      });
    }

    res.json({
      message: "Shelf scanned successfully",
      imagePath,
      shelf_id: shelfId,
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
  } catch (err) { res.status(500).json({ message: err.message }); }
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
    if (!product || !lat || !lng) return res.status(400).json({ message: "product, lat, lng required" });
    const franchises = await Franchise.find();
    const results = franchises
      .filter(f => f.inventory[product] && f.inventory[product] > 0)
      .map(f => ({
        name: f.name,
        address: f.address,
        stock: f.inventory[product],
        distance: calculateDistance(parseFloat(lat), parseFloat(lng), f.lat, f.lng).toFixed(2),
        lat: f.lat, lng: f.lng
      }))
      .sort((a, b) => a.distance - b.distance);
    res.json(results);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

app.get("/admin/franchises", auth("admin"), async (req, res) => {
  try {
    const franchises = await Franchise.find();
    res.json(franchises);
  } catch (err) { res.status(500).json({ message: err.message }); }
});

/* =========================
   START SERVER
========================= */
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Server running at http://localhost:${PORT}`));