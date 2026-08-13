import joblib
import pandas as pd

MODEL_PATH = r"C:\Users\rakhe\Downloads\LANL_RF_Model.pkl"

model = joblib.load(MODEL_PATH)

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


scenarios = {

    "Normal Activity": {
        "USB_Event_Count": 0,
        "Email_Count": 5,
        "HTTP_Count": 20,
        "Logon_Event_Count": 1,
        "Login_Hour": 10,
        "Session_Duration_Min": 120,
        "After_Office_Hours": 0,
        "Successful_Login_Count": 1,
        "Failed_Login_Count": 0,
        "Process_Creation_Count": 10,
        "Privileged_Login_Count": 0,
        "Logoff_Count": 1,
        "Credential_Login_Count": 0,
        "Kerberos_TGT_Count": 0,
        "Kerberos_Service_Count": 0,
        "Credential_Validation_Count": 0
    },

    "Suspicious Activity": {
        "USB_Event_Count": 5,
        "Email_Count": 2,
        "HTTP_Count": 50,
        "Logon_Event_Count": 10,
        "Login_Hour": 2,
        "Session_Duration_Min": 500,
        "After_Office_Hours": 1,
        "Successful_Login_Count": 8,
        "Failed_Login_Count": 15,
        "Process_Creation_Count": 100,
        "Privileged_Login_Count": 8,
        "Logoff_Count": 5,
        "Credential_Login_Count": 10,
        "Kerberos_TGT_Count": 10,
        "Kerberos_Service_Count": 20,
        "Credential_Validation_Count": 15
    }
}


for scenario_name, values in scenarios.items():

    X = pd.DataFrame(
        [[values[name] for name in feature_names]],
        columns=feature_names
    )

    prediction = model.predict(X)[0]
    probabilities = model.predict_proba(X)[0]

    print("\n" + "=" * 60)
    print(scenario_name)
    print("=" * 60)

    print(f"Prediction: {prediction}")

    print("\nProbabilities:")

    for label, probability in zip(model.classes_, probabilities):
        print(f"{label}: {probability:.2%}")