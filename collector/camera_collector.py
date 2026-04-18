import sys
import cv2
from datetime import datetime
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
from config.settings import PHOTOS_DIR

def capture_photo(reason):
    cap = cv2.VideoCapture(0)
    if not cap.isOpened():
        print("Error: Could not access the camera.")
        return None                         

    cap.read()  
    filename = PHOTOS_DIR / f"{datetime.now().strftime('%Y-%m-%d_%H-%M-%S')}_{reason}.jpg"
    ret, frame = cap.read()
    cap.release()
    
    if not ret:
        print("Error: Failed to capture frame.")
        return None
    
    cv2.imwrite(str(filename), frame)
    print(f"Photo saved: {filename}")
    return filename                         
