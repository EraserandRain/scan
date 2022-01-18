#!/bin/bash
export LC_ALL=C
## set input
eth=""
txt=""
read -p "Please input eth name (such as 'enp1s0'): " eth
read -p "Please input ip list path(txt file): " txt
sum=$(cat "$txt"|wc -l)
## script loop
for (( i=0;i<"$sum";i++ ))
do
    iparr[$i]=$(awk 'NR=="'$[$i+1]'"' "$txt")
    ip=${iparr[$i]}
    echo $ip
    ip addr add "$ip" dev "$eth"
    sh OS_Linux_check.sh "$ip"
done
service network restart
mkdir -p dat
mv ./*.dat ./dat/
echo success!
exit 0