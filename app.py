from flask import Flask, request, jsonify
from flask_cors import CORS
import pandas as pd
import joblib
import os

from feature_extraction import extract_url_features

app = Flask(__name__)
CORS(app)  # Allow requests from Chrome Extension

MODEL_PATH = "phishing_model.pkl"

if not os.path.exists(MODEL_PATH):
    raise FileNotFoundError(
        f"{MODEL_PATH} not found. Run 'python train_model.py' first to "
        "train and save the model before starting the Flask app."
    )
clf = joblib.load(MODEL_PATH)


@app.route("/check", methods=["POST"])
def check_url():
    data = request.get_json()
    url = data.get("url")

    # Extract features and convert to DataFrame
    features = extract_url_features(url)
    X_input = pd.DataFrame([features])

    # Get phishing probability
    phishing_score = clf.predict_proba(X_input)[0][1]
    prediction = int(phishing_score >= 0.3)

    return jsonify({
        "score": round(float(phishing_score), 2),
        "prediction": prediction
    })


if __name__ == "__main__":
    app.run(debug=True)
