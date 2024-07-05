import numpy as np
import os.path
import sys
import pandas as pd
from pandas._config.config import is_nonnegative_int


# Show dependency errors due to pecuiliarities in the import. They work fine
import tensorflow as tf
import xgboost as xgb

from sklearn.model_selection import train_test_split
from sklearn.preprocessing import MinMaxScaler
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score
from sklearn.feature_selection import (
    mutual_info_classif,
    SelectKBest,
)


# How to use the Script
if len(sys.argv) < 4:
    print("Usage: python MLTraining.py <classifier_type> <attack_type> <save/test> ")
    sys.exit(1)


classifier_type = sys.argv[1]
if classifier_type not in ["XGB", "NN"]:
    print("Choose one of the options {XGB, NN}")
    sys.exit(1)


option = sys.argv[2]
if option not in ["ddos", "botnet", "infiltration", "sql", "bruteforce"]:
    print("Choose one of the options {ddos, botnet, infiltration, sql, bruteforce}")
    sys.exit(1)

shouldSave = sys.argv[3]
if shouldSave not in ["save", "test"]:
    print("Choose one of the options {save, test}")
    sys.exit(1)


# Fetching the Training Data
combined_df = pd.read_csv(
    "data-preproc/cleanedData/fullyFormattedData/{}Days.csv".format(option),
    skip_blank_lines=True,
    chunksize=100000,
)

for part_df in combined_df:
    x_df = part_df.drop(columns="Label")

    y_df = part_df["Label"]
    y = y_df.values

    # Convert 'y' column to numeric labels (0 for benign, 1 for malicious)

    print("Benign:\t\t", y_df.value_counts()[[0]].sum())
    print("Malicious:\t", y_df.value_counts()[[1]].sum())
    print("EvilPercent:\t", (y_df.value_counts()[[1]].sum() * 100) / x_df.shape[0])
    # x_df.info()

    # This is technically redudant as the Cleaning Script already does it.
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
    if classifier_type == "NN":
        print("Attempting to load Neural Network")
        if os.path.isfile(
            "../ml_models/NN/{}Model.keras".format(option)
        ):  # you won't have a model for first iteration
            print("Found existing Model")
            model = tf.keras.models.load_model(
                "../ml_models/NN/{}Model.keras".format(option)
            )
        else:
            print("Did not find existing Model")
            model = tf.keras.Sequential(
                [
                    tf.keras.layers.Dense(
                        128, activation="relu", input_shape=(X_train.shape[1],)
                    ),  # Increase neurons
                    tf.keras.layers.BatchNormalization(),
                    tf.keras.layers.Dense(64, activation="relu"),  # Decrease neurons
                    tf.keras.layers.BatchNormalization(),
                    tf.keras.layers.Dense(1, activation="sigmoid"),
                ]
            )

        # Compile the model
        model.compile(
            optimizer="adam",
            loss="binary_crossentropy",
            metrics=["accuracy", "recall", "precision"],
        )

        # Train the model
        model.fit(X_train, y_train, epochs=50, batch_size=32, validation_split=0.2)
        # Evaluate the model
        loss, accuracy, recall, precision = model.evaluate(X_test, y_test)
        f1_score = 2 * (precision * recall) / (precision + recall)
        print("Test Accuracy:", accuracy)
        print("Precision: ", precision)
        print("Recall: ", recall)
        print("F1 Score:", f1_score)
        # Save the model
        if shouldSave == "save":
            model.save("../ml_models/NN/{}Model.keras".format(option))

    elif classifier_type == "XGB":
        print("Attemping to load Gradient Boosting Classifier")
        rf_classifier = xgb.XGBClassifier()

        if os.path.isfile(
            "../ml_models/XGB/{}Model.json".format(option)
        ):  # you won't have a model for first iteration
            print("Found existing Model")
            rf_classifier.load_model("../ml_models/XGB/{}Model.json".format(option))

        rf_classifier.fit(X_train, y_train)

        if shouldSave == "save":
            rf_classifier.save_model("../ml_models/XGB/{}Model.json".format(option))

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
