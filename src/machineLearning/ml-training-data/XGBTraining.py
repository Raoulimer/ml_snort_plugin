import numpy as np
import pandas as pd
import os
from sklearn.model_selection import train_test_split
import sys
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import KMeans
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_selection import (
    chi2,
    f_classif,
    mutual_info_classif,
    RFE,
    SelectFromModel,
    SelectKBest,
)

from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
import xgboost as xgb


if len(sys.argv) < 2:
    print("Usage: python attackTypeFormatter.py <option>")
    sys.exit(1)

option = sys.argv[1]
if option not in ["ddos", "botnet", "infiltration", "sql", "bruteforce"]:
    print("Choose one of the options {ddos, botnet, infiltration, sql, bruteforce}")
    sys.exit(1)


combined_df = pd.read_csv(
    "../AIDetection/cleanedData/trainingData/{}Days.csv".format(option),
    skip_blank_lines=True,
    chunksize=100000,
)

fetchBestFeatures = True

for part_df in combined_df:
    x_df = part_df.drop(columns=["Label", "Date", "Time"])

    y_df = part_df["Label"]
    y = y_df.values

    # Convert 'y' column to numeric labels (0 for benign, 1 for malicious)

    print("Benign:\t\t", y_df.value_counts()[[0]].sum())
    print("Malicious:\t", y_df.value_counts()[[1]].sum())
    print("EvilPercent:\t", (y_df.value_counts()[[1]].sum() * 100) / x_df.shape[0])

    x_df.replace([np.inf, -np.inf], np.nan, inplace=True)
    max_finite_value = np.nanmax(x_df.values)
    x_df.fillna(max_finite_value, inplace=True)

    # Scale the data using Min-Max scaling
    scaler = MinMaxScaler()
    X_scaled = scaler.fit_transform(x_df)

    print("Entering Ranking Stage:")
    # Select the top k features
    selector = SelectKBest(mutual_info_classif, k=10)
    X_selected = selector.fit_transform(X_scaled, y)
    selected_features = x_df.columns[selector.get_support()]
    print("Selected Features:", selected_features)

    setprint = False
    if setprint:
        print("Entering Ranking Print:")
        info_gain = mutual_info_classif(X_scaled, y)
        feature_info = pd.DataFrame(
            {"Feature": x_df.columns, "Information Gain": info_gain}
        )
        feature_info_sorted = feature_info.sort_values(
            by="Information Gain", ascending=False
        )
        print(feature_info_sorted.head(10))

    print("Entering Training Stage:")
    # Split the data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X_selected, y, test_size=0.2, random_state=42
    )

    # Define the TensorFlow model
    # Define the TensorFlow model with modified architecture

    rf_classifier = xgb.XGBClassifier()

    if os.path.isfile(
        "/home/angaja/AIDetection/trainedmodels/{}Model.json".format(option)
    ):  # you won't have a model for first iteration
        print("Found existing Model")
        rf_classifier.load_model("trainedmodels/{}Model.json".format(option))

    rf_classifier.fit(X_train, y_train)
    rf_classifier.save_model("trainedmodels/{}Model.json".format(option))

    y_pred = rf_classifier.predict(X_test)

    def calculate_metrics(y_test, y_pred):
        accuracy = accuracy_score(y_test, y_pred)
        precision = precision_score(y_test, y_pred)
        recall = recall_score(y_test, y_pred)
        f1 = f1_score(y_test, y_pred)
        return accuracy, precision, recall, f1

    metrics_dict = {"RF": calculate_metrics(y_test, y_pred)}

    # Print the metrics for each technique
    for technique, metrics in metrics_dict.items():
        accuracy, precision, recall, f1 = metrics
        print(f"Metrics for {technique}:")
        print(f"  Accuracy: {accuracy}")
        print(f"  Precision: {precision}")
        print(f"  Recall: {recall}")
        print(f"  F1 Score: {f1}")
