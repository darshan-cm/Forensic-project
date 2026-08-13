import joblib
import pandas as pd

from features.feature_aggregator import get_features


MODEL_PATH = "models/forensicguard_rf.pkl"

FEATURE_ORDER = [
    "Successful_Login_Count",
    "Failed_Login_Count",
    "Process_Creation_Count",
    "Logoff_Count",
    "Credential_Validation_Count",
    "Total_Events",
    "Login_Hour",
    "After_Office_Hours"
]


def assess_risk(features, attack_probability):
    """
    Combine ML output with observable forensic indicators.

    Process creation alone is not considered sufficient evidence
    for a High-risk classification.
    """

    failed_logins = features["Failed_Login_Count"]
    credential_validation = features["Credential_Validation_Count"]
    successful_logins = features["Successful_Login_Count"]
    total_events = features["Total_Events"]
    process_creations = features["Process_Creation_Count"]

    # Strong authentication-related indicators
    strong_security_activity = (
        failed_logins >= 2 or
        credential_validation >= 1
    )

    # Very high activity combined with security indicators
    high_activity = (
        total_events >= 100 or
        process_creations >= 50
    )

    # ---------------------------------------------------------
    # HIGH RISK
    # ---------------------------------------------------------
    if (
        strong_security_activity and
        (attack_probability >= 0.60 or high_activity)
    ):
        return "High"

    # ---------------------------------------------------------
    # MEDIUM RISK
    # ---------------------------------------------------------
    if strong_security_activity:
        return "Medium"

    if (
        attack_probability >= 0.70 and
        total_events >= 50
    ):
        return "Medium"

    # ML alone should not escalate ordinary process activity
    if (
        attack_probability >= 0.50 and
        total_events >= 20
    ):
        return "Medium"

    # ---------------------------------------------------------
    # LOW RISK
    # ---------------------------------------------------------
    return "Low"


def detect_risk():

    # =========================================================
    # LOAD MODEL
    # =========================================================

    model = joblib.load(MODEL_PATH)

    # =========================================================
    # GET LIVE FEATURES
    # =========================================================

    features = get_features()

    # =========================================================
    # CREATE MODEL INPUT
    # =========================================================

    X = pd.DataFrame(
        [[features[name] for name in FEATURE_ORDER]],
        columns=FEATURE_ORDER
    )

    # =========================================================
    # ML PREDICTION
    # =========================================================

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

    classes = list(model.classes_)

    benign_probability = probabilities[
        classes.index(0)
    ]

    attack_probability = probabilities[
        classes.index(1)
    ]

    # =========================================================
    # FORENSIC RISK ASSESSMENT
    # =========================================================

    final_risk = assess_risk(
        features,
        attack_probability
    )

    # =========================================================
    # OUTPUT
    # =========================================================

    print("\n" + "=" * 60)
    print("FORENSICGUARD AI DETECTION")
    print("=" * 60)

    print("\nLive Features:")

    for name in FEATURE_ORDER:
        print(f"{name}: {features[name]}")

    print("\n" + "-" * 60)

    print(
        "ML Prediction:",
        "Suspicious/Attack"
        if prediction == 1
        else "Benign"
    )

    print(
        f"ML Attack Probability : "
        f"{attack_probability * 100:.2f}%"
    )

    print(
        f"ML Benign Probability : "
        f"{benign_probability * 100:.2f}%"
    )

    print(
        f"\nFinal Forensic Risk    : "
        f"{final_risk}"
    )

    print("\nRisk Assessment:")

    if final_risk == "Low":
        print("Normal or low-risk activity detected.")

    elif final_risk == "Medium":
        print(
            "Potentially suspicious activity detected. "
            "Further investigation recommended."
        )

    else:
        print(
            "Strong suspicious indicators detected. "
            "Immediate forensic investigation recommended."
        )

    return {
        "prediction": int(prediction),
        "attack_probability": float(attack_probability),
        "benign_probability": float(benign_probability),
        "risk": final_risk,
        "features": features
    }


if __name__ == "__main__":
    detect_risk()