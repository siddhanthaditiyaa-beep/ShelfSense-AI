/**
 * Slot → Product Mapper
 * Maps shelf slot numbers to product names using a planogram
 */

// This defines which product sits in which slot on each shelf
const shelfPlanogram = {
  "SHELF_001": {
    1: "Chocolates",
    2: "Chocolates",
    3: "Biscuits",
    4: "Biscuits",
    5: "Chips",
    6: "Chips",
    7: "Juice",
    8: "Juice",
    9: "Soft Drinks",
    10: "Soft Drinks"
  },
  "SHELF_002": {
    1: "Canned Food",
    2: "Canned Food",
    3: "Rice",
    4: "Rice",
    5: "Salt",
    6: "Salt",
    7: "Chocolates",
    8: "Biscuits",
    9: "Chips",
    10: "Juice"
  }
};

function mapSlotsToProducts(shelfId, occupiedSlots, emptySlots) {
  const layout = shelfPlanogram[shelfId];

  if (!layout) {
    throw new Error(`No planogram defined for shelf ${shelfId}`);
  }

  const presentProducts = new Set();
  const missingProducts = new Set();

  occupiedSlots.forEach(slot => {
    const product = layout[slot];
    if (product) presentProducts.add(product);
  });

  emptySlots.forEach(slot => {
    const product = layout[slot];
    if (product) missingProducts.add(product);
  });

  return {
    present_products: Array.from(presentProducts),
    missing_products: Array.from(missingProducts)
  };
}

module.exports = mapSlotsToProducts;