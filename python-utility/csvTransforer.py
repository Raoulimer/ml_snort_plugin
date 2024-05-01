# importing pandas library
import pandas as pd

# reading given csv file
# and creating dataframe
websites = pd.read_csv(
    "../../mlfork/ml_classifiers/tmp/timeouted_connections.txt",
    header=None,
    delimiter=" ",
)

# adding column headings
# websites.columns = ['Name', 'Type', 'Website']

# store dataframe into csv file
websites.to_csv("formatteddetection.csv", index=None)
