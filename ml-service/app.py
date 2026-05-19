print("🔥 app.py loaded")

from flask import Flask, request, jsonify
from PIL import Image
import numpy as np
import os

app = Flask(__name__)

# -------------------------------
# CONFIG
# -------------------------------
TOTAL_SLOTS = 10
EMPTY_THRESHOLD = 220

# -------------------------------
# HEALTH CHECK
# -------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})

# -------------------------------
# PROCESS SHELF IMAGE
# -------------------------------
@app.route("/process-shelf-image", methods=["POST"])
def process_shelf_image():
    data = request.json
    image_path = data.get("imagePath")

    if not image_path:
        return jsonify({"error": "imagePath required"}), 400

    # Node sends paths like /uploads/xyz.jpg
    image_path = image_path.lstrip("/")

    if not os.path.exists(image_path):
        return jsonify({"error": f"Image not found: {image_path}"}), 404

    img = Image.open(image_path).convert("L")
    img_np = np.array(img)

    width, height = img.size
    slot_width = width // TOTAL_SLOTS

    occupied = []
    empty = []

    for i in range(TOTAL_SLOTS):
        x_start = i * slot_width
        x_end = x_start + slot_width
        slot = img_np[:, x_start:x_end]
        avg_brightness = np.mean(slot)

        if avg_brightness < EMPTY_THRESHOLD:
            occupied.append(i + 1)
        else:
            empty.append(i + 1)

    response = {
        "shelf_id": "SHELF_001",
        "total_slots": TOTAL_SLOTS,
        "occupied_slots": len(occupied),
        "empty_slots": len(empty),
        "occupied_slot_numbers": occupied,
        "empty_slot_numbers": empty
    }

    return jsonify(response)

# -------------------------------
# START SERVER (CRITICAL)
# -------------------------------
if __name__ == "__main__":
    print("🚀 Starting Flask ML service on port 5001")
    app.run(host="127.0.0.1", port=5001, debug=True)
