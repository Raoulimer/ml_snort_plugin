import numpy as np
import os.path
import sys
import pandas as pd
from pandas._config.config import is_nonnegative_int
import tensorflow as tf
from sklearn.model_selection import train_test_split
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import MinMaxScaler
from sklearn.cluster import KMeans
from sklearn.decomposition import PCA
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_selection import (
    chi2,
    f_classif,
    mutual_info_classif,
    RFE,
    SelectFromModel,
    SelectKBest,
)

from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score, f1_score, precision_score, recall_score


if len(sys.argv) < 2:
    print("Usage: python attackTypeFormatter.py <option>")
    sys.exit(1)

option = sys.argv[1]
if option not in ["ddos", "botnet", "infiltration", "sql", "bruteforce"]:
    print("Choose one of the options {ddos, botnet, infiltration, sql, bruteforce}")
    sys.exit(1)


# Load the CSV files using pandas
# x_df1 = pd.read_csv("../AIDetection/cleanedData/dirtyData/allcleanDays/Day1_clean.csv", skip_blank_lines=True)
combined_df = pd.read_csv(
    "../AIDetection/cleanedData/trainingData/{}Days.csv".format(option),
    skip_blank_lines=True,
    chunksize=100000,
)

for part_df in combined_df:
    x_df2 = part_df.drop(columns="Label")
    x_df = x_df2.drop(columns="Date")

    y_df = part_df["Label"]
    y = y_df.values

    # Convert 'y' column to numeric labels (0 for benign, 1 for malicious)

    print("Benign:\t\t", y_df.value_counts()[[0]].sum())
    print("Malicious:\t", y_df.value_counts()[[1]].sum())
    print("EvilPercent:\t", (y_df.value_counts()[[1]].sum() * 100) / x_df.shape[0])
    # x_df.info()

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
    if os.path.isfile(
        "/home/angaja/AIDetection/trainedmodels/{}Model.keras".format(option)
    ):  # you won't have a model for first iteration
        print("Found existing Model")
        model = tf.keras.models.load_model("trainedmodels/{}Model.keras".format(option))
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
    model.save("trainedmodels/{}Model.keras".format(option))
