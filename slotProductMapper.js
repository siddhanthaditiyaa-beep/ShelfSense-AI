/**
 * Slot → Product Mapper
 * Uses planogram to map shelf slots to products
 * Admin can update planogram via API
 */

// Default planogram — admin can override this
// Key = shelf ID, Value = object mapping slot number to product key
let shelfPlanogram = {
  "SHELF_001": {
    1: "chocolates",
    2: "chocolates",
    3: "biscuits",
    4: "biscuits",
    5: "chips",
    6: "chips",
    7: "juice",
    8: "juice",
    9: "soft-drinks",
    10: "soft-drinks"
  },
  "SHELF_002": {
    1: "canned-food",
    2: "canned-food",
    3: "rice",
    4: "rice",
    5: "salt",
    6: "salt",
    7: "chocolates",
    8: "biscuits",
    9: "chips",
    10: "juice"
  }
};

function mapSlotsToProducts(shelfId, occupiedSlots, emptySlots) {
  const layout = shelfPlanogram[shelfId];

  if (!layout) {
    // Auto-generate a basic planogram if shelf not defined
    console.log(`No planogram for ${shelfId}, using default mapping`);
    return {
      present_products: [],
      missing_products: []
    };
  }

  const presentProducts = new Set();
  const missingProducts = new Set();
  const presentDetails = {};
  const missingDetails = {};

  occupiedSlots.forEach(slot => {
    const product = layout[slot];
    if (product) {
      presentProducts.add(product);
      presentDetails[product] = (presentDetails[product] || 0) + 1;
    }
  });

  emptySlots.forEach(slot => {
    const product = layout[slot];
    if (product) {
      missingProducts.add(product);
      missingDetails[product] = (missingDetails[product] || 0) + 1;
    }
  });

  return {
    present_products: Array.from(presentProducts),
    missing_products: Array.from(missingProducts),
    present_details: presentDetails,
    missing_details: missingDetails
  };
}

function updatePlanogram(shelfId, slotMapping) {
  shelfPlanogram[shelfId] = slotMapping;
  console.log(`✅ Planogram updated for ${shelfId}`);
}

function getPlanogram(shelfId) {
  if (shelfId) {
    return shelfPlanogram[shelfId] || null;
  }
  return shelfPlanogram;
}

module.exports = { mapSlotsToProducts, updatePlanogram, getPlanogram };