#!/bin/bash
# Zeek və asılılıqların quraşdırılması

echo "Zeek quraşdırılması başlayır..."

# Sistem yeniləmələri
sudo apt update && sudo apt upgrade -y

# Asılılıqların quraşdırılması
sudo apt install -y cmake make gcc g++ flex bison libpcap-dev libssl-dev python3 python3-dev swig zlib1g-dev

# Zeek-in mənbə kodundan quraşdırılması
wget https://download.zeek.org/zeek-6.0.0.tar.gz
tar -xzf zeek-6.0.0.tar.gz
cd zeek-6.0.0

./configure --prefix=/opt/zeek --build-type=release
make -j$(nproc)
sudo make install

# PATH dəyişəninə əlavə edilməsi
echo 'export PATH=/opt/zeek/bin:$PATH' >> ~/.bashrc
source ~/.bashrc

echo "Zeek uğurla quraşdırıldı!"
