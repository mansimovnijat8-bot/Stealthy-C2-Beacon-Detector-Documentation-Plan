#!/bin/bash
# Zeek konfiqurasiyasının tənzimlənməsi

echo "Zeek konfiqurasiyası başlayır..."

# Zeek konfiqurasiya qovluğuna keçid
cd /opt/zeek/etc

# Şəbəkə interfeysinin tənzimlənməsi
INTERFACE=$(ip link show | grep -E '^[0-9]+: eth' | head -1 | cut -d: -f2 | tr -d ' ')
sudo sed -i "s/interface=.*/interface=$INTERFACE/" node.cfg

# Zeek-i işə salmaq
sudo /opt/zeek/bin/zeekctl deploy

echo "Zeek konfiqurasiyası tamamlandı!"
echo "İnterfeys: $INTERFACE"
