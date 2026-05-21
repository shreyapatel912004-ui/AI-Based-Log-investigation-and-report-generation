import os
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'

import warnings
warnings.filterwarnings("ignore")

from pathlib import Path

import numpy as np
import joblib
from tensorflow.keras.models import load_model

from flask import Flask, request, jsonify, render_template
from flask_cors import CORS

BASE_DIR = Path(__file__).resolve().parents[1]
FRONTEND_DIR = BASE_DIR / "frontend"
MODEL_DIR = BASE_DIR / "ml_model"

app = Flask(
    __name__,
    template_folder=str(FRONTEND_DIR / "templates"),
    static_folder=str(FRONTEND_DIR / "static")
)

CORS(app)

# Load model and scaler
model = load_model(MODEL_DIR / 'attack_detection_model.h5')
scaler = joblib.load(MODEL_DIR / 'scaler.pkl')


def smart_verification_engine(raw_log):

    scaled = scaler.transform([raw_log])

    reshaped = scaled.reshape(1,1,11)

    ai_score = model.predict(
        reshaped,
        verbose=0
    )[0][0]


    has_primary_action=(

        raw_log[0]>3 or
        raw_log[5]==1 or
        raw_log[9]==1 or
        raw_log[10]==1
    )


    if has_primary_action:

        if ai_score>0.10:

            verdict="🚨 ATTACK CONFIRMED"
            note="Dangerous action + AI suspicion"

        else:

            verdict="⚠️ HIGH RISK ACTIVITY"
            note="Dangerous action detected even if AI score low"

    elif ai_score>0.30:

        verdict="⚠️ SUSPICIOUS PATTERN"
        note="AI behavioral anomaly detected"

    else:

        verdict="✅ NORMAL"
        note="No threat detected"

    return verdict,f"{ai_score*100:.2f}%",note


# Dashboard page
@app.route('/')
def dashboard():
    return render_template('index.html')


# API endpoint
@app.route('/analyze',methods=['POST'])
def analyze():

    data=request.json.get("log")

    data=list(map(int,data))

    verdict,score,note=smart_verification_engine(data)

    return jsonify({

        "verdict":verdict,
        "score":score,
        "note":note
    })


if __name__=="__main__":
    app.run(debug=True)
