import tensorflow as tf
import numpy as np
import pandas as pd

from sklearn.preprocessing import MinMaxScaler

# Step 1: Load the pre-trained model
model = tf.keras.models.load_model(
    "/home/angaja/mlfork/ml_classifiers/ml_models/malicious_traffic_detection_model.keras"
)  # Replace 'path_to_your_model.h5' with the path to your saved model file

# Load the CSV files using pandas
# x_df1 = pd.read_csv("../AIDetection/cleanedData/dirtyData/allcleanDays/Day1_clean.csv", skip_blank_lines=True)
x_df = pd.read_csv(
    "/home/angaja/mlfork/ml_classifiers/tmp/formattedExtractions.csv",
    skip_blank_lines=True,
)


# INTEGRATE THIS BETTER --> HARDCODING IT IS STUPID
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

X_selected = x_df[best_features]
scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X_selected)
predictions = model.predict(X_scaled)
x_df["Predictions"] = predictions

# Write predictions to a text file
with open(
    "/home/angaja/mlfork/ml_classifiers/tmp/timeouted_connections_results.txt", "w"
) as file:
    for prediction in predictions:
        file.write("{:.2f}\n".format(prediction.item()))
