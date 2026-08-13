import joblib
import pandas as pd

MODEL_PATH = "models/forensicguard_rf.pkl"

FEATURES = [
    "Successful_Login_Count",
    "Failed_Login_Count",
    "Process_Creation_Count",
    "Logoff_Count",
    "Credential_Validation_Count",
    "File_Creation_Count",
    "Registry_Modification_Count",
    "Network_Connection_Count",
    "Image_Loaded_Count",
    "Process_Access_Count",
    "Remote_Thread_Count",
    "Total_Events",
    "Login_Hour",
    "After_Office_Hours"
]

model = joblib.load(MODEL_PATH)


scenarios = {

    "Normal Activity": [
        0, 0, 2, 0, 0,
        0, 0, 0, 0, 0,
        0, 2, 14, 0
    ],

    "Moderate Activity": [
        1, 0, 8, 1, 0,
        2, 0, 1, 5, 0,
        0, 20, 14, 0
    ],

    "Suspicious Activity": [
        2, 5, 40, 0, 2,
        15, 8, 10, 30, 5,
        2, 120, 2, 1
    ]
}


for name, values in scenarios.items():

    X = pd.DataFrame(
        [values],
        columns=FEATURES
    )

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    attack_probability = probabilities[
        list(model.classes_).index(1)
    ]

    if attack_probability >= 0.70:
        risk = "High"
    elif attack_probability >= 0.40:
        risk = "Medium"
    else:
        risk = "Low"

    print("\n" + "=" * 55)
    print(name)
    print("=" * 55)

    print(
        "Prediction:",
        "Suspicious/Attack" if prediction == 1 else "Benign"
    )

    print(
        f"Attack Probability: "
        f"{attack_probability * 100:.2f}%"
    )

    print("Risk Level:", risk)