print("🔥 YOLOv8 Retail Shelf ML Service loading...")

from flask import Flask, request, jsonify
from ultralytics import YOLO
from PIL import Image
import os
import numpy as np

app = Flask(__name__)

MODEL_PATH = "retail_shelf.pt"
if not os.path.exists(MODEL_PATH):
    print(f"⚠️ Custom model not found, using YOLOv8n fallback")
    MODEL_PATH = "yolov8n.pt"

print(f"📥 Loading model from {MODEL_PATH}...")
model = YOLO(MODEL_PATH)
print("✅ Model loaded successfully!")
print(f"📋 Model classes: {model.names}")

LOW_STOCK_THRESHOLD = 3

POSITION_TO_PRODUCT = {
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
}

@app.route("/health", methods=["GET"])
def health():
    return jsonify({
        "status": "ok",
        "model": MODEL_PATH,
        "classes": model.names
    })

@app.route("/process-shelf-image", methods=["POST"])
def process_shelf_image():
    data = request.json
    image_path = data.get("imagePath")
    # Admin can now pass total_slots — defaults to auto-detect
    requested_slots = data.get("total_slots", None)

    if not image_path:
        return jsonify({"error": "imagePath required"}), 400

    local_path = image_path.lstrip("/")

    if not os.path.exists(local_path):
        return jsonify({"error": f"Image not found: {local_path}"}), 404

    try:
        # Run YOLO detection
        results = model(local_path, conf=0.10, verbose=False)
        result = results[0]

        img = Image.open(local_path)
        img_width, img_height = img.size

        print(f"📊 Total YOLO detections: {len(result.boxes)}")
        print(f"🖼️ Image size: {img_width}x{img_height}")

        # ----------------------------------------
        # AUTO DETECT SLOT COUNT
        # Use brightness analysis to count how
        # many distinct product columns exist
        # ----------------------------------------
        img_gray = img.convert("L")
        img_np = np.array(img_gray)

        if requested_slots:
            TOTAL_SLOTS = int(requested_slots)
            print(f"📌 Using admin-specified slots: {TOTAL_SLOTS}")
        else:
            # Auto detect by scanning vertical columns
            # Look for product edges using brightness variation
            col_std = []
            scan_cols = 50  # scan every 50 pixels
            for x in range(0, img_width, scan_cols):
                col = img_np[:, x:x+scan_cols]
                col_std.append(np.std(col))

            # Count peaks in variation — each peak is a product boundary
            threshold = np.mean(col_std) * 0.8
            product_columns = sum(1 for s in col_std if s > threshold)
            TOTAL_SLOTS = max(4, min(product_columns, 15))
            print(f"🔍 Auto-detected slots: {TOTAL_SLOTS}")

        slot_width = img_width / TOTAL_SLOTS

        occupied_slots = set()
        empty_slots_from_model = set()
        detected_products = []
        detection_details = []

        for box in result.boxes:
            x1 = float(box.xyxy[0][0])
            x2 = float(box.xyxy[0][2])
            x_center = (x1 + x2) / 2

            slot_number = int(x_center / slot_width) + 1
            slot_number = min(max(slot_number, 1), TOTAL_SLOTS)

            class_id = int(box.cls[0])
            class_name = model.names[class_id].lower()
            confidence = float(box.conf[0])

            print(f"  Slot {slot_number}: class='{class_name}' conf={confidence:.2f}")

            if class_name == "empty":
                empty_slots_from_model.add(slot_number)
            else:
                occupied_slots.add(slot_number)
                product = POSITION_TO_PRODUCT.get(slot_number, "chocolates")
                detected_products.append(product)
                detection_details.append({
                    "slot": slot_number,
                    "class": class_name,
                    "product": product,
                    "confidence": round(confidence, 2)
                })

        # ----------------------------------------
        # BRIGHTNESS FALLBACK
        # If YOLO misses products, use brightness
        # to determine occupied vs empty slots
        # ----------------------------------------
        if len(occupied_slots) == 0:
            print("⚠️ Using brightness fallback...")
            slot_w = img_width // TOTAL_SLOTS

            for i in range(TOTAL_SLOTS):
                x_start = i * slot_w
                x_end = min(x_start + slot_w, img_width)
                slot_region = img_np[:, x_start:x_end]

                avg_brightness = np.mean(slot_region)
                std_brightness = np.std(slot_region)

                # High variation = product present
                # Low variation + high brightness = empty shelf
                is_occupied = (avg_brightness < 210) or (std_brightness > 25)

                if is_occupied:
                    occupied_slots.add(i + 1)
                    product = POSITION_TO_PRODUCT.get(i + 1, "chocolates")
                    detected_products.append(product)
                    detection_details.append({
                        "slot": i + 1,
                        "class": "brightness_detected",
                        "product": product,
                        "confidence": 0.65
                    })

        # ----------------------------------------
        # HANDLE EXPLICITLY DETECTED EMPTY SLOTS
        # ----------------------------------------
        for s in empty_slots_from_model:
            occupied_slots.discard(s)

        all_slots = set(range(1, TOTAL_SLOTS + 1))
        final_empty = sorted(list(all_slots - occupied_slots))
        final_occupied = sorted(list(occupied_slots))
        unique_products = list(set(detected_products))

        missing_products = list(set([
            POSITION_TO_PRODUCT.get(s, "unknown")
            for s in final_empty
        ]))

        stock_counts = {}
        for product in detected_products:
            stock_counts[product] = stock_counts.get(product, 0) + 1

        # Calculate fill percentage
        fill_percentage = round((len(final_occupied) / TOTAL_SLOTS) * 100, 1)

        response = {
            "shelf_id": data.get("shelf_id", "SHELF_001"),
            "total_slots": TOTAL_SLOTS,
            "occupied_slots": len(final_occupied),
            "empty_slots": len(final_empty),
            "occupied_slot_numbers": final_occupied,
            "empty_slot_numbers": final_empty,
            "present_products": unique_products,
            "missing_products": missing_products,
            "detection_details": detection_details,
            "stock_counts": stock_counts,
            "fill_percentage": fill_percentage,
            "low_stock_alert": len(final_occupied) <= LOW_STOCK_THRESHOLD,
            "total_detections": len(result.boxes)
        }

        return jsonify(response)

    except Exception as e:
        print(f"❌ Error: {str(e)}")
        return jsonify({"error": str(e)}), 500

if __name__ == "__main__":
    print("🚀 Starting Retail Shelf ML service on port 5001")
    app.run(host="127.0.0.1", port=5001, debug=False)