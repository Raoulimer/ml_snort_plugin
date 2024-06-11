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
    - [Attacking the Services](#attacking-the-services)


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

> **Note:** Unfortunately, `makepkg` (specifically `fakeroot`) seems to be VERY slow when running in a Docker container, so the build time is substantial. Note that the base image is Arch, so you will not have access to the APT package manager.
> If you want to install additional packages, you can use `pacman` or the `yay` AUR helper.

You can build from the Dockerfile by running the following command in the projects root directory (feel free to change the naming):
```console
~ docker build -t Raoulimer/ml_snort_plugin:1.0
```
Run the container:
```console
~ docker build -t Raoulimer/ml_snort_plugin:1.0

```
> **WARNING:** `--net=host` will cause the Docker container to use the network stack of the host it is running on. **THIS IS INHERENTLY UNSAFE!** I only recommend using the container for **TESTING** the plugin.
>

The image should be configured to have a python http server running on port 8000 and an ssh daemon running on port 22.
Since the detection model doesn't rely source/destination IPs for Classification you can use some of the provided attack-scripts in 
the test/AttackMethods directory (to be added).

To the rest of the network it will appear as if the services of the docker container are running on its host. You can of course also use your own attack scripts and attack the services from a different machine.



### Attacking the services
> **Note:** While you can technically install the necessary packages required to run the scripts on any distro, I 
> recommend you use kali for this, since a lot of them will be preinstalled. 

**Infiltration:** 
Prompts the user for the target operating system and creates a reverse TCP payload. 
Also prompts the user for the  IP/port he wants to listen on and starts listening for incoming TCP connections. Requires on msfconsole/msfvenom
```console
~ ./infiltrationTestScript.sh
```

**DoS:** 
The DoS Testscript uses the slowhttptest and goldenEye Packages. Since (during the time of creation), the goldeneye package from the kali-rolling mirror was bugged, you will need to clone it directly from the github repo and run the DoS script from the directory that you cloned it into. 
```console
~ ./dosTestScript.sh
```
**Bruteforce:** 
Uses Patator and Hydra in order to attack a ssh server. The ssh configuration in the docker container purposefully allows for Password Authentication with a high number of retries. 
The script prompts the user for a username, target-IP and wordlist path. (default username: builder)
```console
~ ./bruteforceTestScript.sh
```


