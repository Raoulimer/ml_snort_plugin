#!/bin/bash

# Check if aws command is available
if ! command -v aws &>/dev/null; then
	echo "AWS CLI is not installed. Please install AWS CLI to proceed."
	exit 1
fi

aws s3 sync --no-sign-request s3://cse-cic-ids2018/Processed\ Traffic\ Data\ for\ ML\ Algorithms/ .

#Rename the days and remove the bugged 4th
mv Wednesday-14-02-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay1.csv
mv Thursday-15-02-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay2.csv
mv Friday-16-02-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay3.csv

#Dont blame me its their typo
rm Thuesday-20-02-2018_TrafficForML_CICFlowMeter.csv
mv Wednesday-21-02-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay5.csv
mv Thursday-22-02-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay6.csv
mv Friday-23-02-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay7.csv
mv Wednesday-28-02-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay8.csv
mv Thursday-01-03-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay9.csv
mv Friday-02-03-2018_TrafficForML_CICFlowMeter.csv OriginalDirtyDay10.csv
