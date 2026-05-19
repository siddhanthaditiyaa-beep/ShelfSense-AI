from PIL import Image
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import os

# --------------------------------------------------
# CONFIG
# --------------------------------------------------
IMAGE_PATH = r"C:\ml-test\shelf.jpg"
TOTAL_SLOTS = 10        # assume 10 shelf slots
EMPTY_THRESHOLD = 220   # brightness threshold

# --------------------------------------------------
# LOAD IMAGE
# --------------------------------------------------
if not os.path.exists(IMAGE_PATH):
    raise FileNotFoundError(f"Image not found: {IMAGE_PATH}")

img = Image.open(IMAGE_PATH).convert("L")  # grayscale
width, height = img.size

print("Image size:", img.size)

# Convert to numpy for pixel analysis
img_np = np.array(img)

slot_width = width // TOTAL_SLOTS

occupied_slots = []
empty_slots = []

# --------------------------------------------------
# SLOT ANALYSIS
# --------------------------------------------------
for i in range(TOTAL_SLOTS):
    x_start = i * slot_width
    x_end = x_start + slot_width

    slot_region = img_np[:, x_start:x_end]
    avg_brightness = np.mean(slot_region)

    if avg_brightness < EMPTY_THRESHOLD:
        occupied_slots.append(i)
    else:
        empty_slots.append(i)

# --------------------------------------------------
# VISUALIZATION
# --------------------------------------------------
fig, ax = plt.subplots(1, figsize=(12, 5))
ax.imshow(Image.open(IMAGE_PATH))
ax.axis("off")

for i in occupied_slots:
    rect = patches.Rectangle(
        (i * slot_width, 0),
        slot_width,
        height,
        linewidth=2,
        edgecolor="green",
        facecolor="none"
    )
    ax.add_patch(rect)
    ax.text(
        i * slot_width + 5,
        20,
        f"Slot {i+1}",
        color="green",
        fontsize=10,
        weight="bold"
    )

for i in empty_slots:
    rect = patches.Rectangle(
        (i * slot_width, 0),
        slot_width,
        height,
        linewidth=2,
        edgecolor="red",
        facecolor="none"
    )
    ax.add_patch(rect)

plt.title("STEP 9.5 — Slot-Based Shelf Occupancy Detection")
plt.show()

# --------------------------------------------------
# RESULTS
# --------------------------------------------------
print("Total slots:", TOTAL_SLOTS)
print("Occupied slots:", len(occupied_slots))
print("Empty slots:", len(empty_slots))
print("Occupied slot indexes:", occupied_slots)
print("Empty slot indexes:", empty_slots)
