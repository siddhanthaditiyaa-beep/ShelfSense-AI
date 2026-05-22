require("dotenv").config();
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

mongoose.connect(process.env.MONGODB_URI).then(async () => {
  console.log("Connected to MongoDB...");

  const StoreSchema = new mongoose.Schema({
    name: String, ownerName: String,
    ownerEmail: { type: String, lowercase: true },
    password: String, plan: { type: String, default: "free" },
    isActive: { type: Boolean, default: true },
    openingTime: { type: String, default: "09:00" },
    closingTime: { type: String, default: "22:00" },
    alertEmail: String, weatherCity: { type: String, default: "Mumbai" }
  });

  const ItemSchema = new mongoose.Schema({
    storeId: mongoose.Schema.Types.ObjectId,
    key: String, name: String, stock: Number,
    salesHistory: [Number], price: Number,
    category: String, supplier: String,
    minStockLevel: Number
  });

  const Store = mongoose.model("Store", StoreSchema);
  const Item = mongoose.model("Item", ItemSchema);

  const existing = await Store.findOne({ ownerEmail: "test@test.com" });
  if (existing) {
    console.log("✅ test@test.com already exists! Updating password...");
    existing.password = await bcrypt.hash("test123", 12);
    await existing.save();
    console.log("✅ Password reset to test123");
  } else {
    const hashedPassword = await bcrypt.hash("test123", 12);
    const store = await Store.create({
      name: "Test Store", ownerName: "Test Owner",
      ownerEmail: "test@test.com", password: hashedPassword,
      plan: "free", alertEmail: "test@test.com"
    });
    await Item.insertMany([
      { storeId: store._id, key: "chocolates", name: "Chocolates", stock: 15, salesHistory: [2,3,2,4,3], price: 149, category: "snacks", supplier: "Nestle", minStockLevel: 3 },
      { storeId: store._id, key: "biscuits", name: "Biscuits", stock: 20, salesHistory: [1,2,3,2,1], price: 49, category: "snacks", supplier: "Britannia", minStockLevel: 5 },
      { storeId: store._id, key: "chips", name: "Chips", stock: 2, salesHistory: [3,4,3,5,4], price: 29, category: "snacks", supplier: "Lays", minStockLevel: 4 },
      { storeId: store._id, key: "juice", name: "Juice", stock: 0, salesHistory: [2,2,3,2,3], price: 99, category: "beverages", supplier: "Tropicana", minStockLevel: 4 },
      { storeId: store._id, key: "soft-drinks", name: "Soft Drinks", stock: 25, salesHistory: [4,5,4,6,5], price: 59, category: "beverages", supplier: "Coca-Cola", minStockLevel: 5 }
    ]);
    console.log("✅ Test store created — test@test.com / test123");
  }

  mongoose.disconnect();
  console.log("Done!");
});