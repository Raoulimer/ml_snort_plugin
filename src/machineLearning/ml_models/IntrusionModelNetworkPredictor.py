# import tensorflow as tf
import numpy as np
import pandas as pd
import sys
import os

os.environ["TF_CPP_MIN_LOG_LEVEL"] = "3"
import tensorflow as tf
from xgboost import XGBClassifier
from sklearn.preprocessing import MinMaxScaler
import json

if len(sys.argv) < 3:
    print(
        "Usage: python IntrusionModelNetworkPredictor.py <attack_type> <classifier_type>"
    )
    sys.exit(1)

attack_type = sys.argv[1]
if attack_type not in ["ddos", "botnet", "infiltration", "sql", "bruteforce"]:
    print("Choose one of the options {ddos, botnet, infiltration, sql, bruteforce}")
    sys.exit(1)

classifier_type = sys.argv[2]
if classifier_type not in ["XGB", "NN"]:
    print("Choose one of the options {XGB, NN}")
    sys.exit(1)

currdir = os.path.dirname(__file__)
rel_path_to_tmp = os.path.join(currdir, "../../../tmp/")


# IS faster than dynamically loading during execution!
def setBestfeatures(option):
    with open(os.path.join(currdir, "best_features.json"), "r") as file:
        config = json.load(file)
    return config.get(option, [])


# Load the CSV files using pandas

x_df = pd.read_csv(
    rel_path_to_tmp + "formattedExtractions.csv",
    skip_blank_lines=True,
)

x_df.replace([np.inf, -np.inf], np.nan, inplace=True)
max_finite_value = np.nanmax(x_df.values)
x_df.fillna(max_finite_value, inplace=True)

best_features = setBestfeatures(attack_type)
X_selected = x_df[best_features]

scaler = MinMaxScaler()
X_scaled = scaler.fit_transform(X_selected)

# Load the pre-trained model
if classifier_type == "XGB":
    model = XGBClassifier()
    model.load_model(currdir + "/XGB/{}Model.json".format(attack_type))

elif classifier_type == "NN":
    model = tf.keras.models.load_model(
        currdir + "/NN/{}Model.keras".format(attack_type)
    )

if model is None:
    raise RuntimeError("Model loading failed. Please check the model path and format.")


predictions = model.predict(X_scaled)
x_df["Predictions"] = predictions

# Write predictions to a text file
with open(
    rel_path_to_tmp + "timeouted_connections_results{}.txt".format(attack_type),
    "w",
) as file:
    for prediction in predictions:
        file.write("{:.2f}\n".format(prediction.item()))

print("Debug: Predictions for {} Attack Type finished\n".format(attack_type))
