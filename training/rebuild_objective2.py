import os
import joblib
import pandas as pd

from sklearn.model_selection import train_test_split
from sklearn.ensemble import (
    RandomForestClassifier,
    ExtraTreesClassifier,
    HistGradientBoostingClassifier
)
from sklearn.metrics import (
    accuracy_score,
    roc_auc_score,
    classification_report,
    confusion_matrix
)
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline
from sklearn.linear_model import LogisticRegression


# ============================================================
# CONFIGURATION
# ============================================================

DATASET = r"C:\Users\rakhe\forensicguard_objective2_final.csv"
MODEL_PATH = r"C:\project\p2\models\forensicguard_rf.pkl"

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
# LOAD ORIGINAL LABELED DATA
# ============================================================

print("=" * 75)
print("FORENSICGUARD OBJECTIVE-2 MODEL OPTIMIZATION")
print("=" * 75)

print("\nLoading labeled dataset...")

df = pd.read_csv(DATASET)

df = df[
    FEATURES + [TARGET]
].dropna()

print(f"Original dataset shape: {df.shape}")

print("\nOriginal class distribution:")
print(df[TARGET].value_counts())


# ============================================================
# REALISTIC BENIGN BEHAVIOR
#
# These represent ordinary activities demonstrated during
# the ForensicGuard live monitoring tests.
#
# IMPORTANT:
# We are NOT adding file/window events as ML features.
# They remain Objective-1 forensic events.
# ============================================================

benign_samples = [

    # --------------------------------------------------------
    # IDLE / NO ACTIVITY
    # --------------------------------------------------------

    [0, 0, 0, 0, 0, 0, 8, 0],
    [0, 0, 0, 0, 0, 0, 10, 0],
    [0, 0, 0, 0, 0, 0, 12, 0],
    [0, 0, 0, 0, 0, 0, 14, 0],
    [0, 0, 0, 0, 0, 0, 16, 0],

    # --------------------------------------------------------
    # SINGLE NORMAL APPLICATION
    # --------------------------------------------------------

    # Notepad
    [0, 0, 1, 0, 0, 1, 10, 0],
    [0, 0, 1, 0, 0, 1, 12, 0],
    [0, 0, 1, 0, 0, 1, 14, 0],
    [0, 0, 1, 0, 0, 1, 16, 0],

    # Brave / Chrome
    [0, 0, 1, 0, 0, 1, 10, 0],
    [0, 0, 1, 0, 0, 1, 12, 0],
    [0, 0, 2, 0, 0, 2, 14, 0],
    [0, 0, 2, 0, 0, 2, 16, 0],

    # WhatsApp
    [0, 0, 1, 0, 0, 1, 10, 0],
    [0, 0, 1, 0, 0, 1, 12, 0],
    [0, 0, 2, 0, 0, 2, 14, 0],

    # VS Code
    [0, 0, 1, 0, 0, 1, 10, 0],
    [0, 0, 2, 0, 0, 2, 12, 0],
    [0, 0, 3, 0, 0, 3, 14, 0],

    # File Explorer
    [0, 0, 1, 0, 0, 1, 10, 0],
    [0, 0, 1, 0, 0, 1, 12, 0],
    [0, 0, 2, 0, 0, 2, 16, 0],

    # --------------------------------------------------------
    # NORMAL MULTI-APPLICATION USAGE
    # --------------------------------------------------------

    [0, 0, 2, 0, 0, 2, 9, 0],
    [0, 0, 3, 0, 0, 3, 10, 0],
    [0, 0, 3, 0, 0, 3, 12, 0],
    [0, 0, 4, 0, 0, 4, 13, 0],
    [0, 0, 4, 0, 0, 4, 14, 0],
    [0, 0, 5, 0, 0, 5, 15, 0],
    [0, 0, 6, 0, 0, 6, 16, 0],

    # --------------------------------------------------------
    # NORMAL USER LOGIN + APPLICATION USAGE
    # --------------------------------------------------------

    [1, 0, 1, 0, 0, 2, 9, 0],
    [1, 0, 2, 0, 0, 3, 10, 0],
    [1, 0, 2, 0, 0, 3, 12, 0],
    [1, 0, 3, 0, 0, 4, 13, 0],
    [1, 0, 4, 0, 0, 5, 14, 0],
    [1, 0, 5, 0, 0, 6, 16, 0],

    # --------------------------------------------------------
    # NORMAL ACTIVITY AFTER OFFICE HOURS
    # --------------------------------------------------------

    [0, 0, 1, 0, 0, 1, 18, 1],
    [0, 0, 2, 0, 0, 2, 19, 1],
    [0, 0, 3, 0, 0, 3, 20, 1],
    [1, 0, 2, 0, 0, 3, 18, 1],
    [1, 0, 3, 0, 0, 4, 19, 1],

    # --------------------------------------------------------
    # NORMAL MODERATE ACTIVITY
    # --------------------------------------------------------

    [0, 0, 4, 0, 0, 4, 11, 0],
    [0, 0, 5, 0, 0, 5, 12, 0],
    [0, 0, 6, 0, 0, 6, 13, 0],
    [0, 0, 7, 0, 0, 7, 14, 0],
    [0, 0, 8, 0, 0, 8, 15, 0],

    [1, 0, 4, 0, 0, 5, 11, 0],
    [1, 0, 5, 0, 0, 6, 12, 0],
    [1, 0, 6, 0, 0, 7, 14, 0],
]


benign_df = pd.DataFrame(
    benign_samples,
    columns=FEATURES
)

benign_df[TARGET] = 0


print("\nRealistic benign samples added:", len(benign_df))


# ============================================================
# COMBINE DATA
# ============================================================

final_df = pd.concat(
    [
        df,
        benign_df
    ],
    ignore_index=True
)

final_df = final_df.sample(
    frac=1,
    random_state=42
).reset_index(drop=True)


print("\n" + "=" * 75)
print("FINAL TRAINING DATA")
print("=" * 75)

print(
    f"Original samples : {len(df)}"
)

print(
    f"Added benign     : {len(benign_df)}"
)

print(
    f"Final samples    : {len(final_df)}"
)

print("\nClass distribution:")

print(
    final_df[TARGET].value_counts()
)

print("\nClass percentage:")

print(
    (
        final_df[TARGET]
        .value_counts(normalize=True)
        * 100
    ).round(2)
)


# ============================================================
# TRAIN / TEST SPLIT
# ============================================================

X = final_df[FEATURES]
y = final_df[TARGET]

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y
)

print("\n" + "=" * 75)
print("TRAIN / TEST SPLIT")
print("=" * 75)

print(
    "Training samples:",
    len(X_train)
)

print(
    "Testing samples :",
    len(X_test)
)


# ============================================================
# MODELS
# ============================================================

models = {

    "Random Forest - Balanced": RandomForestClassifier(
        n_estimators=800,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features="sqrt",
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    ),

    "Random Forest - Tuned": RandomForestClassifier(
        n_estimators=1000,
        max_depth=20,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features=None,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    ),

    "Extra Trees": ExtraTreesClassifier(
        n_estimators=1000,
        max_depth=None,
        min_samples_split=2,
        min_samples_leaf=1,
        max_features=None,
        class_weight="balanced",
        random_state=42,
        n_jobs=-1
    ),

    "Hist Gradient Boosting": HistGradientBoostingClassifier(
        max_iter=300,
        learning_rate=0.05,
        max_leaf_nodes=31,
        l2_regularization=1.0,
        random_state=42
    ),

    "Logistic Regression": Pipeline([
        (
            "scaler",
            StandardScaler()
        ),
        (
            "classifier",
            LogisticRegression(
                max_iter=2000,
                class_weight="balanced",
                random_state=42
            )
        )
    ])
}


# ============================================================
# MODEL COMPARISON
# ============================================================

results = []

best_model = None
best_name = None
best_accuracy = -1
best_auc = -1


print("\n" + "=" * 75)
print("MODEL COMPARISON")
print("=" * 75)


for name, model in models.items():

    print(
        f"\nTraining: {name}"
    )

    model.fit(
        X_train,
        y_train
    )

    predictions = model.predict(
        X_test
    )

    probabilities = model.predict_proba(
        X_test
    )

    classes = list(
        model.classes_
    )

    attack_index = classes.index(1)

    attack_probability = probabilities[
        :,
        attack_index
    ]

    accuracy = accuracy_score(
        y_test,
        predictions
    )

    roc_auc = roc_auc_score(
        y_test,
        attack_probability
    )

    results.append({
        "Model": name,
        "Accuracy": accuracy,
        "ROC_AUC": roc_auc
    })

    print(
        f"Accuracy : {accuracy * 100:.2f}%"
    )

    print(
        f"ROC-AUC  : {roc_auc:.4f}"
    )

    # Accuracy first, ROC-AUC second
    if (
        accuracy > best_accuracy
        or
        (
            accuracy == best_accuracy
            and roc_auc > best_auc
        )
    ):

        best_accuracy = accuracy
        best_auc = roc_auc
        best_model = model
        best_name = name


# ============================================================
# RESULTS TABLE
# ============================================================

results_df = pd.DataFrame(
    results
)

results_df = results_df.sort_values(
    [
        "Accuracy",
        "ROC_AUC"
    ],
    ascending=False
)


print("\n" + "=" * 75)
print("MODEL PERFORMANCE")
print("=" * 75)

print(
    results_df.to_string(
        index=False,
        formatters={
            "Accuracy": "{:.4f}".format,
            "ROC_AUC": "{:.4f}".format
        }
    )
)


# ============================================================
# BEST MODEL
# ============================================================

print("\n" + "=" * 75)
print("BEST MODEL")
print("=" * 75)

print(
    "Model   :",
    best_name
)

print(
    f"Accuracy: "
    f"{best_accuracy * 100:.2f}%"
)

print(
    f"ROC-AUC : "
    f"{best_auc:.4f}"
)


# ============================================================
# FINAL EVALUATION
# ============================================================

final_predictions = best_model.predict(
    X_test
)

final_probabilities = best_model.predict_proba(
    X_test
)

final_classes = list(
    best_model.classes_
)

final_attack_index = final_classes.index(1)

final_attack_probability = (
    final_probabilities[
        :,
        final_attack_index
    ]
)


print("\n=== CLASSIFICATION REPORT ===")

print(
    classification_report(
        y_test,
        final_predictions,
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
        final_predictions
    )
)


# ============================================================
# FEATURE IMPORTANCE
# ============================================================

if hasattr(
    best_model,
    "feature_importances_"
):

    importance = pd.DataFrame({

        "Feature": FEATURES,

        "Importance":
            best_model.feature_importances_

    })

    importance = importance.sort_values(
        "Importance",
        ascending=False
    )

    print(
        "\n=== FEATURE IMPORTANCE ==="
    )

    print(
        importance.to_string(
            index=False
        )
    )


# ============================================================
# CONTROLLED SCENARIO TEST
# ============================================================

print("\n" + "=" * 75)
print("CONTROLLED SCENARIO TEST")
print("=" * 75)


scenarios = {

    "Idle": [
        0, 0, 0, 0, 0, 0, 12, 0
    ],

    "Normal Notepad": [
        0, 0, 1, 0, 0, 1, 12, 0
    ],

    "Normal Brave / Chrome": [
        0, 0, 2, 0, 0, 2, 12, 0
    ],

    "Normal WhatsApp": [
        0, 0, 2, 0, 0, 2, 14, 0
    ],

    "Normal VS Code": [
        0, 0, 3, 0, 0, 3, 14, 0
    ],

    "Normal Multi-App": [
        0, 0, 5, 0, 0, 5, 14, 0
    ],

    "Normal Login + Apps": [
        1, 0, 4, 0, 0, 5, 14, 0
    ],

    "Normal After-Hours": [
        0, 0, 3, 0, 0, 3, 19, 1
    ],

    "Moderate Suspicious": [
        1, 2, 8, 0, 1, 12, 14, 0
    ],

    "Controlled Attack": [
        2, 5, 40, 0, 2, 49, 2, 1
    ]
}


for name, values in scenarios.items():

    test = pd.DataFrame(
        [values],
        columns=FEATURES
    )

    prediction = best_model.predict(
        test
    )[0]

    probabilities = best_model.predict_proba(
        test
    )[0]

    attack_probability = probabilities[
        final_classes.index(1)
    ]

    print(
        "\n" + "-" * 60
    )

    print(
        name
    )

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
    best_model,
    MODEL_PATH
)


print("\n" + "=" * 75)
print("BEST MODEL SAVED")
print("=" * 75)

print(
    MODEL_PATH
)

print("\nFeatures used:")

for i, feature in enumerate(
    FEATURES,
    1
):

    print(
        f"{i}. {feature}"
    )


print(
    "\nObjective-2 optimization complete."
)