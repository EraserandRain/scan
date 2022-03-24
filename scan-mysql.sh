#!/bin/bash
export LC_ALL=C
## set input
eth=""
txt="./iplist/linux-device.txt"

read -p "Please input eth name (for example 'enp1s0'): " eth
# read -p "Please input ip list path(txt file,for example './iplist/iplist.txt'): " txt
sum=$(cat "$txt"|wc -l)
## script loop
for (( i=0;i<"$sum";i++ ))
do
    iparr[$i]=$(awk 'NR=="'$[$i+1]'"' "$txt")
    ip=${iparr[$i]}
    echo $ip
    ip addr add "$ip" dev "$eth"
    sh DB_Linux_MySQL_check.sh "$ip" /server/abchosting/mysql/bin trunkey trunkey7771502 3306
done
service network restart
mkdir -p ./dat/mysql/
rm -rf ./dat/mysql/*.dat
mv ./DB_Linux_MySQL*.dat ./dat/mysql/
echo success!
exit 0
