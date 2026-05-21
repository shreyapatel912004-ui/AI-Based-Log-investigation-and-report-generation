import os
from pathlib import Path

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"

import numpy as np
from sklearn.metrics import accuracy_score, classification_report, confusion_matrix, f1_score
from tensorflow.keras.models import load_model


BASE_DIR = Path(__file__).resolve().parents[1]
MODEL_DIR = BASE_DIR / "ml_model"
MODEL_PATH = MODEL_DIR / "attack_detection_model.h5"
X_PATH = MODEL_DIR / "X_lstm_final (1).npy"
Y_PATH = MODEL_DIR / "y_labels_final (1).npy"


def find_best_threshold(y_true, probabilities):
    best_threshold = 0.5
    best_f1 = 0

    for threshold in np.arange(0.1, 0.91, 0.01):
        predictions = (probabilities >= threshold).astype(int)
        score = f1_score(y_true, predictions, zero_division=0)
        if score > best_f1:
            best_threshold = float(threshold)
            best_f1 = float(score)

    return round(best_threshold, 2), round(best_f1, 4)


def main():
    X = np.load(X_PATH)
    y = np.load(Y_PATH)
    model = load_model(MODEL_PATH, compile=False)

    probabilities = model.predict(X, verbose=0).reshape(-1)
    best_threshold, best_f1 = find_best_threshold(y, probabilities)
    predictions = (probabilities >= best_threshold).astype(int)

    print("Dataset shape:", X.shape)
    print("Label counts:", dict(zip(*np.unique(y, return_counts=True))))
    print("Best threshold:", best_threshold)
    print("Best F1 score:", best_f1)
    print("Accuracy:", round(accuracy_score(y, predictions), 4))
    print("Confusion matrix:")
    print(confusion_matrix(y, predictions))
    print("Classification report:")
    print(classification_report(y, predictions, target_names=["NORMAL", "ATTACK"], zero_division=0))


if __name__ == "__main__":
    main()
