import subprocess
import json

import joblib
import pandas as pd

from features.feature_aggregator import get_features


# ============================================================
# CONFIGURATION
# ============================================================

MODEL_PATH = "models/forensicguard_rf.pkl"


# ============================================================
# MODEL FEATURE ORDER
#
# IMPORTANT:
# Keep this EXACTLY the same as the trained model.
# USB is NOT inserted into the ML model.
# ============================================================

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


# ============================================================
# CURRENT USB STATUS
# ============================================================

def get_usb_status():

    """
    Detect actual removable USB storage / portable devices.

    Internal USB controllers, hubs and interfaces are ignored.
    """

    command = [
        "powershell",
        "-NoProfile",
        "-Command",
        """
        $devices = Get-CimInstance Win32_PnPEntity |
            Where-Object {
                $_.PNPDeviceID -like 'USB*' -and
                $_.Status -eq 'OK' -and
                $_.Name -notmatch 'USB Root Hub' -and
                $_.Name -notmatch 'USB Hub' -and
                $_.Name -notmatch 'Host Controller' -and
                $_.Name -notmatch 'Generic USB Hub' -and
                $_.Name -notmatch 'USB Composite Device' -and
                $_.Name -notmatch 'ADB Interface'
            }

        $realDevice = $devices | Where-Object {
            $_.Name -match 'OPPO|F19|Phone|Android|MTP|Portable|Storage|Mass'
        }

        if ($realDevice) {
            Write-Output "YES"
        }
        else {
            Write-Output "NO"
        }
        """
    ]

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=5
        )

        return result.stdout.strip().upper() == "YES"

    except Exception as error:

        print(
            f"[USB Status] Unable to determine current USB status: "
            f"{error}"
        )

        return False


# ============================================================
# FORENSIC RISK ASSESSMENT
# ============================================================

def assess_risk(
    features,
    attack_probability,
    usb_connected
):

    failed_logins = features[
        "Failed_Login_Count"
    ]

    credential_validation = features[
        "Credential_Validation_Count"
    ]

    total_events = features[
        "Total_Events"
    ]

    process_creations = features[
        "Process_Creation_Count"
    ]

    # ========================================================
    # STRONG SECURITY INDICATORS
    # ========================================================

    strong_security_activity = (
        failed_logins >= 2 or
        credential_validation >= 1
    )

    # ========================================================
    # HIGH ACTIVITY
    # ========================================================

    high_activity = (
        total_events >= 100 or
        process_creations >= 50
    )

    # ========================================================
    # USB + SUSPICIOUS ACTIVITY
    #
    # USB alone is NOT malicious.
    # It becomes relevant only when combined with suspicious
    # behavioral evidence.
    # ========================================================

    usb_suspicious_activity = (
        usb_connected and
        attack_probability >= 0.70 and
        total_events >= 20
    )

    # ========================================================
    # HIGH RISK
    # ========================================================

    if (
        strong_security_activity and
        (
            attack_probability >= 0.60 or
            high_activity
        )
    ):
        return "High"

    if (
        usb_connected and
        strong_security_activity and
        attack_probability >= 0.60
    ):
        return "High"

    # ========================================================
    # MEDIUM RISK
    # ========================================================

    if strong_security_activity:
        return "Medium"

    if usb_suspicious_activity:
        return "Medium"

    if (
        attack_probability >= 0.70 and
        total_events >= 50
    ):
        return "Medium"

    if (
        attack_probability >= 0.50 and
        total_events >= 20
    ):
        return "Medium"

    # ========================================================
    # LOW RISK
    # ========================================================

    return "Low"


# ============================================================
# MAIN DETECTION
# ============================================================

def detect_risk():

    # ========================================================
    # LOAD MODEL
    # ========================================================

    model = joblib.load(
        MODEL_PATH
    )

    # ========================================================
    # GET LIVE FEATURES
    # ========================================================

    features = get_features()

    # ========================================================
    # GET CURRENT USB STATUS
    # ========================================================

    usb_connected = get_usb_status()

    # ========================================================
    # CREATE MODEL INPUT
    # ========================================================

    X = pd.DataFrame(
        [
            [
                features[name]
                for name in FEATURE_ORDER
            ]
        ],
        columns=FEATURE_ORDER
    )

    # ========================================================
    # ML PREDICTION
    # ========================================================

    prediction = model.predict(X)[0]

    probabilities = model.predict_proba(X)[0]

    classes = list(
        model.classes_
    )

    benign_probability = probabilities[
        classes.index(0)
    ]

    attack_probability = probabilities[
        classes.index(1)
    ]

    # ========================================================
    # FINAL FORENSIC RISK
    # ========================================================

    final_risk = assess_risk(
        features,
        attack_probability,
        usb_connected
    )

    # ========================================================
    # OUTPUT
    # ========================================================

    print("\n" + "=" * 60)
    print("FORENSICGUARD AI DETECTION")
    print("=" * 60)

    print("\nLive Features:")

    for name in FEATURE_ORDER:

        print(
            f"{name}: "
            f"{features[name]}"
        )

    # ========================================================
    # USB STATUS
    # ========================================================

    print("\nUSB Forensic Indicator:")

    print(
        "USB Device Currently Connected: "
        + (
            "YES"
            if usb_connected
            else "NO"
        )
    )

    # ========================================================
    # ML OUTPUT
    # ========================================================

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

    # ========================================================
    # FINAL RISK
    # ========================================================

    print(
        f"\nFinal Forensic Risk    : "
        f"{final_risk}"
    )

    print("\nRisk Assessment:")

    if final_risk == "Low":

        # ----------------------------------------------------
        # Explain elevated ML probability when applicable.
        # ----------------------------------------------------

        if attack_probability >= 0.50:

            print(
                "Elevated ML suspicion detected, but no strong "
                "forensic indicators are currently present. "
                "Current activity volume is insufficient to "
                "classify the endpoint as Medium or High risk."
            )

        else:

            print(
                "Normal or low-risk activity detected."
            )

    elif final_risk == "Medium":

        if usb_connected:

            print(
                "Potentially suspicious activity detected "
                "along with a currently connected USB device. "
                "Further investigation recommended."
            )

        else:

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

        "attack_probability": float(
            attack_probability
        ),

        "benign_probability": float(
            benign_probability
        ),

        "risk": final_risk,

        "usb_connected": usb_connected,

        "features": features
    }


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":

    detect_risk()