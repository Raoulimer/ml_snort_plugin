import pandas as pd
import numpy as np
import sys


dayNr = sys.argv[1]
if dayNr not in ["1", "2", "3", "5", "6", "7", "8", "9", "10"]:
    print("Choose one of the options choose a number from 1 to 10 (excluding 4)")
    sys.exit(1)


day = pd.read_csv("OriginalDirtyDay{}.csv".format(dayNr))

# AI generated line, but it basically just removes rows for which the entry is the (repeated) column name
day.drop(day.loc[day["Label"] == "Label"].index, inplace=True)


uninformative_columns = []

for col in day.columns:
    if day[col].nunique() == 1:
        # fix non-numeric values (only affects some badly formatted days)
        # add columbns with only one unique value to array
        day[col] = pd.to_numeric(day[col], errors="coerce")
        uninformative_columns.append(col)


# I dont want the model to learn "All DDOS attacks happen on tuesdays"
uninformative_columns.append("Timestamp")

print(uninformative_columns)

day.drop(columns=uninformative_columns, inplace=True)


# Index the attack types
day.replace(to_replace="Benign", value=0, inplace=True)
day.replace(to_replace="Bot", value=1, inplace=True)
day.replace(to_replace="Brute(Force|force)", value=2, inplace=True, regex=True)
day.replace(to_replace="DoS attacks-.+", value=3, inplace=True, regex=True)
day.replace(to_replace="DDOS attack-.+", value=3, inplace=True, regex=True)
day.replace(to_replace="Infilteration", value=4, inplace=True)
day.replace(to_replace="SQL Injection", value=5, inplace=True)


day = day.astype("float64")

# Remove NA values and replace Infinite values
day.dropna(inplace=True)
day.drop_duplicates(inplace=True)
day.replace([np.inf, -np.inf], np.nan, inplace=True)
max_finite_value = np.nanmax(day.values)
day.fillna(max_finite_value, inplace=True)

day.to_csv("cleanedData/Day{}_clean.csv".format(dayNr), index=False)
