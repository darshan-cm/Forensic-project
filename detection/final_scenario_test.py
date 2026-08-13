import joblib
import pandas as pd

MODEL_PATH = "models/forensicguard_rf.pkl"

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

model = joblib.load(MODEL_PATH)


def assess_risk(features, attack_probability):

    failed = features["Failed_Login_Count"]
    credential = features["Credential_Validation_Count"]
    total = features["Total_Events"]
    processes = features["Process_Creation_Count"]

    strong_security_activity = (
        failed >= 2 or credential >= 1
    )

    high_activity = (
        total >= 100 or processes >= 50
    )

    if strong_security_activity and (
        attack_probability >= 0.60 or high_activity
    ):
        return "High"

    if strong_security_activity:
        return "Medium"

    if attack_probability >= 0.70 and total >= 50:
        return "Medium"

    if attack_probability >= 0.50 and total >= 20:
        return "Medium"

    return "Low"


# Controlled suspicious scenario
values = [
    2,    # Successful_Login_Count
    5,    # Failed_Login_Count
    40,   # Process_Creation_Count
    0,    # Logoff_Count
    2,    # Credential_Validation_Count
    120,  # Total_Events
    2,    # Login_Hour
    1     # After_Office_Hours
]

features = dict(zip(FEATURES, values))

X = pd.DataFrame([values], columns=FEATURES)

prediction = model.predict(X)[0]
probabilities = model.predict_proba(X)[0]

classes = list(model.classes_)

attack_probability = probabilities[classes.index(1)]
benign_probability = probabilities[classes.index(0)]

risk = assess_risk(
    features,
    attack_probability
)

print("\n" + "=" * 60)
print("FORENSICGUARD FINAL SUSPICIOUS SCENARIO TEST")
print("=" * 60)

print("\nControlled Features:")

for name, value in features.items():
    print(f"{name}: {value}")

print("\n" + "-" * 60)

print(
    "ML Prediction:",
    "Suspicious/Attack" if prediction == 1 else "Benign"
)

print(
    f"ML Attack Probability: "
    f"{attack_probability * 100:.2f}%"
)

print(
    f"ML Benign Probability: "
    f"{benign_probability * 100:.2f}%"
)

print(f"Final Forensic Risk: {risk}")