import os

# Suppress TensorFlow logs
os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
os.environ["TF_ENABLE_ONEDNN_OPTS"] = "0"

import joblib
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model

tf.config.set_visible_devices([], 'GPU')

# Get the directory where THIS file is located
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
MODEL_DIR = os.path.join(BASE_DIR, "ml_model")

scaler_path = os.path.join(MODEL_DIR, "forensic_scaler.pkl")
model_path = os.path.join(MODEL_DIR, "forensic_lstm_model.h5")

print("Loading scaler from:", scaler_path)
print("Loading model from:", model_path)

scaler = joblib.load(scaler_path)
model = load_model(model_path, compile=False)

# ✅ ADD THIS (prints only once)
print("\n===== SCALER TRAINED RANGES =====")
print("Feature Min:", scaler.data_min_)
print("Feature Max:", scaler.data_max_)
print("==================================\n")


def forensic_ai_check(raw_log_list):

    print("\n===========================")
    print("Raw Input:", raw_log_list)

    raw_array = np.array(raw_log_list, dtype=np.float32).reshape(1, -1)
    print("Raw Array:", raw_array)

    scaled_data = scaler.transform(raw_array)
    print("Scaled Data:", scaled_data)

    reshaped_data = scaled_data.reshape(1, 1, 11)
    print("Reshaped Shape:", reshaped_data.shape)

    prediction = model.predict(reshaped_data, verbose=0)
    prediction_score = float(prediction[0][0])

    print("Raw Prediction Score:", prediction_score)
    print("===========================\n")

    return {
        "is_attack": prediction_score > 0.5,
        "confidence": round(prediction_score * 100, 2)
    }
