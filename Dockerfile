FROM archlinux:latest

# Update the system and install necessary packages
RUN pacman -Syu --noconfirm && \
  pacman -S --noconfirm sudo base-devel git net-tools go boost openssh wget ; exit


#Adding our user
RUN useradd -m builder
RUN echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
RUN echo -n 'builder:1234' | chpasswd

USER builder

WORKDIR /home/builder

# Setting environment variables for makepkg directories
ENV BUILDDIR=/home/builder/snort/build
ENV PKGDEST=/home/builder/snort/packages
ENV SRCDEST=/home/builder/snort/sources
ENV SRCPKGDEST=/home/builder/snort/srcpackages
ENV LOGDEST=/home/builder/snort/logs


#Im doing this with an AUR Helper to make the Dockerfile shorter, 
#avoiding manually building all of snorts depdencies (not all of them have binary packages)
RUN git clone https://aur.archlinux.org/yay.git
RUN cd yay; makepkg -si --noconfirm

#Installing snort from the AUR 
RUN yay -S snort --answerclean N --answerdiff N --noconfirm ;

USER root

# Installs XGBoost and tensforflow depdencies
# Adapted from https://linuxhandbook.com/dockerize-python-apps/
ENV PATH="/root/miniconda3/bin:${PATH}"
ARG PATH="/root/miniconda3/bin:${PATH}"
RUN wget https://repo.anaconda.com/miniconda/Miniconda3-latest-Linux-x86_64.sh \
  && mkdir /root/.conda \
  && bash Miniconda3-latest-Linux-x86_64.sh -b \
  && rm -f Miniconda3-latest-Linux-x86_64.sh \
  && echo "Running $(conda --version)" && \
  conda init bash && \
  . /root/.bashrc && \
  conda update conda && \
  conda create -n testenv && \
  conda activate testenv && \
  conda install python=3.12.2 xgboost=2.0.3 pandas=2.2.1 scikit-learn=1.4.2 numpy=1.26.4 && \
  pip install tensorflow==2.16.1 

# Enable Password Authentication for the ssh server, increase the amount of tries before user lockout and setup the ssh daemon
RUN ssh-keygen -A
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config; sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/# deny = 3/deny = 1000000000000000/' /etc/security/faillock.conf
RUN mkdir -p /var/run/sshd

# Set up the working directory for a very simple HTTP server
RUN mkdir myserver; cd myserver; touch superSecretFile;

# Installing the plugin:
# Note: We need to make install as root cause we're installing to /usr/<path>
USER builder
COPY . /home/builder/myplugin
USER root
RUN cd /home/builder/myplugin/build; rm -rf *; cmake ..; make; make install;
RUN echo "ml_classifiers={classifier_type="XGB", mal_threshold_perc=89, tt_expired=61, iteration_interval=19 }" >> /etc/snort/snort.lua

#Creating a startup script that starts the ssh daemon and the python http server
RUN echo $'#!/bin/bash\n/usr/bin/sshd\ncd myserver\npython -m http.server 8000 &' > startupscript.sh && chmod +x startupscript.sh
CMD ["/bin/bash", "-c", "./startupscript.sh && /bin/bash "]




