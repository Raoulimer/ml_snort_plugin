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
    print("Usage: python FlowClassifier.py <attack_type> <classifier_type>")
    sys.exit(1)


attack_types = ["ddos", "botnet", "infiltration", "sql", "bruteforce"]
chosen_attack_type = sys.argv[1]

if chosen_attack_type not in attack_types + ["all"]:
    print("Valid Options = {ddos, botnet, infiltration, sql, bruteforce, all}")
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


# -----------------------------------------------
def loadcsv(a_type):
    x_df = pd.read_csv(
        rel_path_to_tmp + "formattedExtractions.csv",
        skip_blank_lines=True,
    )

    x_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    max_finite_value = np.nanmax(x_df.values)
    x_df.fillna(max_finite_value, inplace=True)

    best_features = setBestfeatures(a_type)
    X_selected = x_df[best_features]

    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(X_selected)
    return X_scaled


# -----------------------------------------------
def predict(x_model, atype):
    X_scaled = loadcsv(atype)
    predictions = x_model.predict(X_scaled)
    with open(
        rel_path_to_tmp + "expired_connections_results{}.txt".format(atype),
        "w",
    ) as file:
        for prediction in predictions:
            file.write("{:.2f}\n".format(prediction.item()))

    print("Debug: Predictions for {} Attack Type finished\n".format(atype))


# -----------------------------------------------
# Load the pre-trained model
if classifier_type == "XGB":
    model = XGBClassifier()
    model.load_model(currdir + "/XGB/{}Model.json".format(chosen_attack_type))
    predict(model, chosen_attack_type)

elif classifier_type == "NN":
    for attack_type in attack_types:
        model = tf.keras.models.load_model(
            currdir + "/NN/{}Model.keras".format(attack_type)
        )
        predict(model, attack_type)

if model is None:
    raise RuntimeError("Model loading failed. Please check the model path and format.")
