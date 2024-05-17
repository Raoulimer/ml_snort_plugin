# import tensorflow as tf
import numpy as np
import pandas as pd
import sys
from xgboost import XGBClassifier
from sklearn.preprocessing import MinMaxScaler


if len(sys.argv) < 2:
    print("Usage: python IntrusionModelNetworkPredictor.py <option>")
    sys.exit(1)

option = sys.argv[1]
if option not in ["ddos", "botnet", "infiltration", "sql", "bruteforce"]:
    print("Choose one of the options {ddos, botnet, infiltration, sql, bruteforce}")
    sys.exit(1)


def setBestfeatures(option):
    if option == "ddos":
        best_features = [
            "Dst Port",
            "TotLen Fwd Pkts",
            "Fwd Pkt Len Max",
            "Fwd Pkt Len Mean",
            "Bwd Pkt Len Max",
            "Fwd IAT Min",
            "Fwd Header Len",
            "Fwd Seg Size Avg",
            "Subflow Fwd Bytes",
            "Init_Win_bytes_forward",
        ]
    elif option == "botnet":
        best_features = [
            "Dst Port",
            "Flow Duration",
            "Flow Pkts/s",
            "Flow IAT Mean",
            "Flow IAT Max",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Max",
            "Fwd IAT Min",
            "Fwd Pkts/s",
        ]
    elif option == "infiltration":  # NOT USING NEURAL NETWORK NOT SET
        best_features = [
            "Dst Port",
            "Flow IAT Max",
            "Fwd IAT Total",
            "Fwd IAT Max",
            "Bwd IAT Total",
            "Bwd IAT Max",
            "Fwd Header Len",
            "Init_Win_bytes_forward",
            "min_seg_size_forward",
            "Idle Max",
        ]
    elif option == "sql":  # NOT USING NEURAL NETWORK
        best_features = [
            "Dst Port",  # This should be Protocol
            "Flow IAT Min",
            "Fwd IAT Total",
            "Fwd IAT Mean",
            "Fwd IAT Min",
            "PSH Flag Count",
            "ACK Flag Count",
            "Down/Up Ratio",
            "Init_Win_bytes_forward",
            "min_seg_size_forward",
        ]
    elif option == "bruteforce":
        best_features = [
            "Dst Port",
            "Flow Duration",
            "Flow IAT Mean",
            "Fwd Header Len",
            "Bwd Header Len",
            "Fwd Pkts/s",
            "Bwd Pkts/s",
            "Init_Win_bytes_forward",
            "Init_Win_bytes_backward",
            "min_seg_size_forward",
        ]
    else:
        best_features = []

    return best_features


# Step 1: Load the pre-trained model
model = XGBClassifier()
model.load_model(
    "/home/angaja/privateRepo/ml_classifiers/ml_models/XGB/{}Model.json".format(option)
)  # Load the CSV files using pandas
# x_df1 = pd.read_csv("../AIDetection/cleanedData/dirtyData/allcleanDays/Day1_clean.csv", skip_blank_lines=True)
x_df = pd.read_csv(
    "/home/angaja/privateRepo/ml_classifiers/tmp/formattedExtractions.csv",
    skip_blank_lines=True,
)

x_df.replace([np.inf, -np.inf], np.nan, inplace=True)
max_finite_value = np.nanmax(x_df.values)
x_df.fillna(max_finite_value, inplace=True)

best_features = setBestfeatures(option)
X_selected = x_df[best_features]

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X_selected)


predictions = model.predict(X_scaled)
x_df["Predictions"] = predictions

# Write predictions to a text file
with open(
    "/home/angaja/privateRepo/ml_classifiers/tmp/timeouted_connections_results{}.txt".format(
        option
    ),
    "w",
) as file:
    for prediction in predictions:
        file.write("{:.2f}\n".format(prediction.item()))
