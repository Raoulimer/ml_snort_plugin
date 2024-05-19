FROM archlinux:latest

# Create a new user named 'builder'



# Update the system and install necessary packages
RUN pacman -Syu --noconfirm && \
  pacman -S --noconfirm sudo base-devel git net-tools; exit



RUN useradd -m builder

RUN echo "builder ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers

RUN pacman -S go --noconfirm 

# Switch to the new user
USER builder

WORKDIR /home/builder
# Set environment variables for makepkg directories
ENV BUILDDIR=/home/builder/snort/build
ENV PKGDEST=/home/builder/snort/packages
ENV SRCDEST=/home/builder/snort/sources
ENV SRCPKGDEST=/home/builder/snort/srcpackages
ENV LOGDEST=/home/builder/snort/logs
# Clone the Snort repository and install it


RUN git clone https://aur.archlinux.org/yay.git

RUN cd yay; makepkg -si --noconfirm

RUN yay -S snort --answerclean N --answerdiff N --noconfirm 

# Switch back to the root user
USER root

# Optionally, clean up the build files
RUN rm -rf /tmp/snort-build

USER builder

COPY . .
