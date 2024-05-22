import pandas as pd
import sys


def load_and_concatenate_data(option):
    if option == "ddos":
        x_df2 = pd.read_csv(
            "Day2_clean.csv",
            skip_blank_lines=True,
        )
        x_df3 = pd.read_csv(
            "Day3_clean.csv",
            skip_blank_lines=True,
        )
        x_df5 = pd.read_csv(
            "Day5_clean.csv",
            skip_blank_lines=True,
        )
        data = pd.concat([x_df2, x_df3, x_df5], ignore_index=True)
    elif option == "bruteforce":
        x_df1 = pd.read_csv(
            "Day1_clean.csv",
            skip_blank_lines=True,
        )
        x_df6 = pd.read_csv(
            "Day6_clean.csv",
            skip_blank_lines=True,
        )
        x_df7 = pd.read_csv(
            "Day7_clean.csv",
            skip_blank_lines=True,
        )
        data = pd.concat([x_df1, x_df6, x_df7], ignore_index=True)
    elif option == "sql":
        x_df6 = pd.read_csv(
            "Day6_clean.csv",
            skip_blank_lines=True,
        )
        x_df7 = pd.read_csv(
            "Day7_clean.csv",
            skip_blank_lines=True,
        )
        data = pd.concat([x_df6, x_df7], ignore_index=True)
    elif option == "infiltration":
        x_df8 = pd.read_csv(
            "Day8_clean.csv",
            skip_blank_lines=True,
        )
        x_df9 = pd.read_csv(
            "Day9_clean.csv",
            skip_blank_lines=True,
        )

        data = pd.concat([x_df8, x_df9], ignore_index=True)
    elif option == "botnet":
        x_df10 = pd.read_csv(
            "Day10_clean.csv",
            skip_blank_lines=True,
        )
        data = x_df10
    else:
        raise ValueError(
            "Invalid option. Choose one of: ddos, bruteforce, sql, infiltration, botnet"
        )

    return data


# Check if option is provided from command line
if len(sys.argv) < 2:
    print("Usage: python attackTypeFormatter.py <option>")
    sys.exit(1)

option = sys.argv[1]

# Load and concatenate data based on option
data = load_and_concatenate_data(option)

instances_label_0 = data.query("Label == 0")

# Filter instances based on label
if option == "ddos":
    instances_label_1 = data.query("Label == 3")
    instances_label_1["Label"] = 1
    combined_df = pd.concat([instances_label_0, instances_label_1])
elif option == "bruteforce":
    instances_label_1 = data.query("Label == 2")
    instances_label_1["Label"] = 1
    combined_df = pd.concat([instances_label_0, instances_label_1])
elif option == "sql":
    instances_label_1 = data.query("Label == 5")
    instances_label_0_small = data.query(
        "Label == 0"
    ).sample(
        instances_label_1.size * 10
    )  # fixes class imbalance, but shows how easy it is to manipulate performance metrics
    instances_label_1["Label"] = 1
    combined_df = pd.concat([instances_label_0_small, instances_label_1])
elif option == "infiltration":
    instances_label_1 = data.query("Label == 4")
    instances_label_1["Label"] = 1
    combined_df = pd.concat([instances_label_0, instances_label_1])
elif option == "botnet":
    instances_label_1 = data.query("Label == 1")
    instances_label_1["Label"] = 1
    combined_df = pd.concat([instances_label_0, instances_label_1])

else:
    raise ValueError(
        "Invalid option. Choose one of: ddos, bruteforce, sql, infiltration"
    )


shuffled = combined_df.sample(frac=1)
shuffled.to_csv(f"fullyFormattedData/{option}Days.csv", index=False)
