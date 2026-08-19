import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)


# ============================================================
# PATHS
# ============================================================

DATASET_PATH = r"C:\Users\rakhe\forensicguard_objective2_final.csv"
MODEL_PATH = r"C:\project\p2\models\forensicguard_rf.pkl"

# ============================================================
# EXACT LIVE FEATURES
# ============================================================

FEATURES = [
    "Successful_Login_Count",
    "Failed_Login_Count",
    "Process_Creation_Count",
    "Logoff_Count",
    "Credential_Validation_Count",
    "Total_Events",
    "Login_Hour",
    "After_Office_Hours"
]

TARGET = "Attack_Label"


# ============================================================
# LOAD DATASET
# ============================================================

print("=" * 70)
print("FORENSICGUARD FINAL OBJECTIVE-2 TRAINING")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Dataset shape: {df.shape}")


# ============================================================
# VALIDATION
# ============================================================

required_columns = FEATURES + [TARGET]

missing_columns = [
    col for col in required_columns
    if col not in df.columns
]

if missing_columns:
    raise ValueError(
        f"Missing required columns: {missing_columns}"
    )

df = df[required_columns].copy()

df = df.dropna()

print(f"Rows after cleaning: {len(df)}")

print("\nClass distribution:")
print(df[TARGET].value_counts())

print("\nClass percentages:")
print(
    (df[TARGET].value_counts(normalize=True) * 100)
    .round(2)
)


# ============================================================
# FEATURES / LABEL
# ============================================================

X = df[FEATURES]
y = df[TARGET]


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\n" + "=" * 70)
print("DATA SPLIT")
print("=" * 70)

print(f"Training samples: {len(X_train)}")
print(f"Testing samples : {len(X_test)}")


# ============================================================
# RANDOM FOREST
# ============================================================

print("\nTraining FINAL Random Forest...")

model = RandomForestClassifier(
    n_estimators=400,
    max_depth=12,
    min_samples_leaf=3,
    min_samples_split=6,
    class_weight="balanced",
    random_state=42,
    n_jobs=-1
)

model.fit(X_train, y_train)

print("Training completed.")


# ============================================================
# TEST SET PREDICTION
# ============================================================

predictions = model.predict(X_test)

probabilities = model.predict_proba(X_test)

classes = list(model.classes_)

attack_index = classes.index(1)

attack_probabilities = probabilities[:, attack_index]


# ============================================================
# RESULTS
# ============================================================

accuracy = accuracy_score(
    y_test,
    predictions
)

roc_auc = roc_auc_score(
    y_test,
    attack_probabilities
)

print("\n" + "=" * 70)
print("FORENSICGUARD FINAL OBJECTIVE-2 MODEL")
print("=" * 70)

print(f"\nAccuracy : {accuracy * 100:.2f}%")
print(f"ROC-AUC  : {roc_auc:.4f}")

print("\n=== CLASSIFICATION REPORT ===")

print(
    classification_report(
        y_test,
        predictions,
        target_names=[
            "Benign",
            "Suspicious/Attack"
        ]
    )
)

print("=== CONFUSION MATRIX ===")

print(
    confusion_matrix(
        y_test,
        predictions
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

importance = pd.DataFrame({
    "Feature": FEATURES,
    "Importance": model.feature_importances_
})

importance = importance.sort_values(
    "Importance",
    ascending=False
)

print("\n=== FEATURE IMPORTANCE ===")

print(
    importance.to_string(
        index=False
    )
)


# ============================================================
# CONTROLLED SCENARIO TESTS
# ============================================================

print("\n" + "=" * 70)
print("CONTROLLED SCENARIO TEST")
print("=" * 70)


scenarios = {

    "Idle / No Activity": [
        0, 0, 0, 0, 0, 0, 12, 0
    ],

    "Normal Application Usage": [
        0, 0, 2, 0, 0, 3, 12, 0
    ],

    "Moderate Activity": [
        1, 0, 8, 0, 0, 12, 14, 0
    ],

    "Suspicious Activity": [
        2, 5, 40, 0, 2, 120, 2, 1
    ]
}


for scenario_name, values in scenarios.items():

    scenario_df = pd.DataFrame(
        [values],
        columns=FEATURES
    )

    prediction = model.predict(
        scenario_df
    )[0]

    probability = model.predict_proba(
        scenario_df
    )[0]

    attack_probability = probability[
        classes.index(1)
    ]

    print("\n" + "-" * 60)
    print(scenario_name)

    print(
        "Prediction:",
        "Suspicious/Attack"
        if prediction == 1
        else "Benign"
    )

    print(
        f"Attack Probability: "
        f"{attack_probability * 100:.2f}%"
    )


# ============================================================
# SAVE MODEL
# ============================================================

os.makedirs(
    os.path.dirname(MODEL_PATH),
    exist_ok=True
)

joblib.dump(
    model,
    MODEL_PATH
)

print("\n" + "=" * 70)
print("FINAL MODEL SAVED")
print("=" * 70)

print(MODEL_PATH)

print("\nFeatures used:")

for i, feature in enumerate(FEATURES, 1):
    print(f"{i}. {feature}")

print("\nObjective-2 training complete.")