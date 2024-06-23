# importing pandas library
import pandas as pd
import os

# reading given csv file
# and creating dataframe
os.system("pwd")
currdir = os.path.dirname(__file__)
rel_path_to_tmp = os.path.join(currdir, "../../tmp/")
print("Debug", rel_path_to_tmp + "timeouted_connections.txt")

# This path is necessary since this script is being called from the ml_models directory
predictions = pd.read_csv(
    rel_path_to_tmp + "timeouted_connections.txt",
    header=None,
    delimiter=" ",
)

predictions.columns = [
    "Dst Port",
    "Flow Duration",
    "Total Fwd Pkts",
    "Total Backward Pkts",
    "TotLen Fwd Pkts",
    "TotLen Bwd Pkts",
    "Fwd Pkt Len Max",
    "Fwd Pkt Len Min",
    "Fwd Pkt Len Mean",
    "Fwd Pkt Len Std",
    "Bwd Pkt Len Max",
    "Bwd Pkt Len Min",
    "Bwd Pkt Len Mean",
    "Bwd Pkt Len Std",
    "Flow Bytes/s",
    "Flow Pkts/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Len",
    "Bwd Header Len",
    "Fwd Pkts/s",
    "Bwd Pkts/s",
    "Min Pkt Len",
    "Max Pkt Len",
    "Pkt Len Mean",
    "Pkt Len Std",
    "Pkt Len Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Pkt Size",
    "Fwd Seg Size Avg",
    "Bwd Seg Size Avg",
    "Fwd Header Len",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Pkts/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Pkts/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Pkts",
    "Subflow Fwd Bytes",
    "Subflow Bwd Pkts",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]  # store dataframe into csv file

# Doing the Scaling here would force us to scale ALL of the features --> SLOW!!

predictions.to_csv(rel_path_to_tmp + "formattedExtractions.csv")
print("Debug: finished transforming Expired Connection")
