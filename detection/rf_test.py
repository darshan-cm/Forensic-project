import joblib
#import numpy as np
import pandas as pd

from features.feature_aggregator import get_features


MODEL_PATH = r"C:\Users\rakhe\Downloads\LANL_RF_Model.pkl"


model = joblib.load(MODEL_PATH)

features = get_features()

feature_names = [
    "USB_Event_Count",
    "Email_Count",
    "HTTP_Count",
    "Logon_Event_Count",
    "Login_Hour",
    "Session_Duration_Min",
    "After_Office_Hours",
    "Successful_Login_Count",
    "Failed_Login_Count",
    "Process_Creation_Count",
    "Privileged_Login_Count",
    "Logoff_Count",
    "Credential_Login_Count",
    "Kerberos_TGT_Count",
    "Kerberos_Service_Count",
    "Credential_Validation_Count"
]

X = pd.DataFrame(
    [[features[name] for name in feature_names]],
    columns=feature_names
)

prediction = model.predict(X)[0]
probability = model.predict_proba(X)[0]

print("\n=== FORENSICGUARD ML DETECTION ===\n")

for name in feature_names:
    print(f"{name}: {features[name]}")

print("\n-------------------------------")
print(f"Risk Prediction : {prediction}")

print("\nRisk Probability:")
for label, prob in zip(model.classes_, probability):
    print(f"{label}: {prob:.2%}")