import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import os

DATA_PATH = os.path.expanduser("~/ids_project/data/dataset.csv")
MODEL_DIR = os.path.expanduser("~/ids_project/models")
os.makedirs(MODEL_DIR, exist_ok=True)

df = pd.read_csv(DATA_PATH)

FEATURES = ["packet_count", "total_bytes", "duration", "avg_packet_size",
            "packets_per_second", "unique_dst_ports"]

X = df[FEATURES]
y = df["label"]

# --- Split into train/test, keeping class proportions similar in both ---
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.25, random_state=42, stratify=y
)

# ---------- Model 1: Random Forest (supervised, known attack types) ----------
print("Training Random Forest...")
rf = RandomForestClassifier(
    n_estimators=100,
    class_weight="balanced",   # compensates for scan dominating the dataset
    random_state=42
)
rf.fit(X_train, y_train)

y_pred = rf.predict(X_test)
print("\n--- Random Forest Results ---")
print(classification_report(y_test, y_pred))
print("Confusion matrix (rows=actual, cols=predicted):")
print("Labels order:", sorted(y.unique()))
print(confusion_matrix(y_test, y_pred, labels=sorted(y.unique())))

joblib.dump(rf, os.path.join(MODEL_DIR, "random_forest.pkl"))

# ---------- Model 2: Isolation Forest (unsupervised, trained on benign only) ----------
print("\nTraining Isolation Forest (on benign traffic only)...")
benign_only = X[y == "benign"]

iso = IsolationForest(
    n_estimators=100,
    contamination=0.1,   # rough guess at expected anomaly rate; tune later
    random_state=42
)
iso.fit(benign_only)

# Test it against the full test set: -1 = anomaly (flag as suspicious), 1 = normal
iso_preds = iso.predict(X_test)
anomaly_labels = ["anomaly" if p == -1 else "normal" for p in iso_preds]
true_binary = ["normal" if lbl == "benign" else "anomaly" for lbl in y_test]

print("\n--- Isolation Forest Results (benign vs. anything else) ---")
print(classification_report(true_binary, anomaly_labels))

joblib.dump(iso, os.path.join(MODEL_DIR, "isolation_forest.pkl"))

print(f"\nBoth models saved to {MODEL_DIR}")
