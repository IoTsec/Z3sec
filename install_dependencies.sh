#!/bin/bash

# Install dependencies for Z3sec on Ubuntu 16.10.

echo ">>> Updating system"
sudo apt-get update -y && sudo apt-get upgrade -y
echo ">>> Installing repo dependencies"
sudo apt-get install -y \
    build-essential \
    cmake \
    doxygen \
    git \
    gnuradio \
    gnuradio-dev \
    ipython \
    libarmadillo-dev \
    libblas-dev \
    libboost-chrono-dev \
    libboost-date-time-dev \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libboost-serialization-dev \
    libboost-system-dev \
    libboost-test-dev \
    libboost-thread-dev \
    libcppunit-dev \
    libcppunit-subunit-dev \
    libgcrypt-dev \
    libgflags-dev \
    libgnutls-openssl-dev \
    libgoogle-glog-dev \
    libgtest-dev \
    liblapack-dev \
    liblog4cpp5-dev \
    mercurial \
    python-cairo \
    python-crypto \
    python-dev \
    python-gtk2 \
    python-numpydoc \
    python-serial \
    python-setuptools \
    python-sphinx \
    python-tk \
    python-usb \
    swig \
    swig3.0 \
    tcpdump \
    xterm
    #python-pip \

#echo ">>> Installing uhd and gnuradio"
#sudo pip install pybombs
#pybombs recipes add gr-recipes https://github.com/gnuradio/gr-recipes.git
#pybombs recipes add gr-etcetera git+https://github.com/gnuradio/gr-etcetera.git
#sudo pybombs prefix init /usr/local
#sudo pybombs -p /usr/local install uhd gnuradio

source_dir=`pwd`
dependencies="$source_dir"/dependencies
# creating working directory:
mkdir "$dependencies"
cd "$dependencies"

echo ">>> Creating global gnuradio config"
sudo cp "$source_dir"/patch/grc.conf /etc/gnuradio/conf.d/grc.conf

#echo ">>> Installing scapy-com"
#hg clone https://bitbucket.org/secdev/scapy-com
#cd scapy-com
#sudo python setup.py install

cd "$dependencies"

echo ">>> Installing scapy-radio"
hg clone https://bitbucket.org/cybertools/scapy-radio
cd scapy-radio
# checkout version with old scapy:
hg up -C 14:980029ae0bbb
./install.sh
# patch scapy dot15d4/zigbee:
sudo cp "$source_dir"/patch/dot15d4.py /usr/local/lib/python2.7/dist-packages/scapy/layers/dot15d4.py

cd "$dependencies"

echo ">>> Installing KillerBee"
git clone https://github.com/riverloopsec/killerbee.git
cd killerbee
# patch scapy_extensions.py and GoodFET.py before installing
cp "$source_dir"/patch/scapy_extensions.py killerbee/scapy_extensions.py
#cp "$source_dir"/killerbee/GoodFET.py killerbee/GoodFET.py
sudo python setup.py install

cd "$dependencies"

echo ">>> Installing gr-foo"
git clone https://github.com/bastibl/gr-foo.git
cd gr-foo
mkdir build && cd build/
cmake .. && make
sudo make install
sudo ldconfig

cd "$dependencies"

echo ">>> Installing gr-ieee802.15.4"
git clone git://github.com/bastibl/gr-ieee802-15-4.git
cd gr-ieee802-15-4
mkdir build && cd build/
cmake .. && make
sudo make install
sudo ldconfig

cd "$source_dir"

echo ">>> Downloading UHD image"
sudo uhd_images_downloader

echo ">>> Installing z3sec_zigbee.grc"
cp "$source_dir"/patch/z3sec_zigbee.grc ~/.scapy/radio/

echo ">>> Installing wireshark"
sudo apt-get install -y wireshark

echo ">>> Done."
