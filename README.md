# ml_classifiers

**ml_classifiers** is a Snort 3 Machine Learning-based Inspector for Network Traffic Bi-directional Flow Classification.

Aim is to adapt for usage with models trained on the CIC IDS 2018 dataset.
Uses Multithreading in order to run multiple attack-type specific models at once.

**NOTE:** `connection.cc` and `connection.h` are NOT MY ORIGINAL CODE. They are taken from Inutimura's `ml_classifiers` plugin, although I refactored the code and separated it into header and source files.

Here is a barebones description of how to use the plugin and train additional classifiers. For a more detailed explanation on what the individual scripts do, please refer to the paper (to be attached).

## Table of Contents

- [How to Build and Run the Plugin](#how-to-build-and-run-the-plugin)
- [How to Train Machine Learning Classifiers](#how-to-train-machine-learning-classifiers)
- [How to Test the Plugin (Dockerfile)](#how-to-test-the-plugin-dockerfile)

## How to Build and Run the Plugin

Create a build directory in the project's root directory and proceed like with any other CMake build:
```console
~ mkdir build; cd build
~ cmake ..
```
You can also run `make` normally, but for faster build times use multiple jobs:
```console
~ make -j $(nproc)
```
Run `make install` as the root user:
```console
# make install
```
Add the plugin to your `snort.lua` in order to activate it:
```console
# echo "ml_classifiers = {"XGB"}" >> /etc/snort/snort.lua.
```
Specify the location of the plugin directory you installed the plugin in. You will need to replace the network interface and rule file paths according to your needs. What matters here is the plugin path:
```console
# snort -c /etc/snort/snort.lua -R /etc/snort/rules/local.rules \
        -i enp24s0 --plugin-path /usr/local/snort/lib/snort/plugins/alternative  \
        --daq-dir /usr/lib/daq/ -A none
```

## How to Train Machine Learning Classifiers

From the project root directory, navigate to the following directory and run the fetch script (you might need to make it executable):
```console
~ cd src/machineLearning/originalData; ./fetchscript.sh
```
Navigate to the data-preproc directory, run the cleaning script:
```console
~ cd ../data-preproc/ ; python dataCleaner.py
```
Navigate to the cleanedData directory, run the grouping script:
```console
~ cd cleanedData ; python attackTypedFormatter.py
```
Navigate to the ml-training-data directory, run the training script:
```console
~ cd ../../ 
~ python attackTypedFormatter.py <classifier_type> <attack_type> <save/test>
```

## How to Test the Plugin (Dockerfile)

I still need to add instructions for this.

