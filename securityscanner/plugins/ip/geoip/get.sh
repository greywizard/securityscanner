wget -N http://geolite.maxmind.com/download/geoip/database/GeoLiteCountry/GeoIP.dat.gz
gunzip GeoIP.dat.gz
mv GeoIP.dat /usr/local/share/GeoIP/
wget -N http://download.maxmind.com/download/geoip/database/asnum/GeoIPASNum.dat.gz
gunzip GeoIPASNum.dat.gz
mv GeoIPASNum.dat /usr/local/share/GeoIP/