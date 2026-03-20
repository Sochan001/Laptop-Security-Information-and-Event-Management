import sys
import cv2
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import PHOTOS_DIR

def capture_photo(reason):
    print("Collecting camera events...\n")
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Error: Could not access the camera.")
        return

    cap.read()
    filename = PHOTOS_DIR / f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{reason}.jpg"
    cv2.imwrite(filename, cap.read()[1])
    print(f"Photo saved: {filename}")
    # As we know cap.read() returns a tuple (ret, frame), where ret is a boolean indicating if the frame was read successfully and frame is the captured image.
    # By using cap.read()[1], we directly access the captured image without checking the return value.
    cap.release()

capture_photo("Manual capture")