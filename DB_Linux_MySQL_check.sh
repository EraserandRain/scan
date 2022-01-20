#!/bin/bash
[ $# -ne 5 ] && {
	echo "Usage: sh DB_Linux_MySQL_check.sh ip InstallHomePath DatabaseUser DatabasePwd DatabasePort";
	exit 1;
}

ipaddr=$1
InstallHomePath=$2
DatabaseUser=$3
DatabasePwd=$4
DatabasePort=$5
template='linux_mysql_all'
role='全部'
subtype='DB_Linux_MySQL'
testtype='/数据库/DB_Linux_MySQL'

id_array=(
"CU_DB_Linux_MySQL_B_6.3.1"
"CU_DB_Linux_MySQL_B_6.3.10"
"CU_DB_Linux_MySQL_B_6.3.11"
"CU_DB_Linux_MySQL_B_6.3.12"
"CU_DB_Linux_MySQL_B_6.3.13"
"CU_DB_Linux_MySQL_B_6.3.14"
"CU_DB_Linux_MySQL_B_6.3.15"
"CU_DB_Linux_MySQL_B_6.3.16"
"CU_DB_Linux_MySQL_B_6.3.17"
"CU_DB_Linux_MySQL_B_6.3.18"
"CU_DB_Linux_MySQL_B_6.3.19"
"CU_DB_Linux_MySQL_B_6.3.2"
"CU_DB_Linux_MySQL_B_6.3.20"
"CU_DB_Linux_MySQL_B_6.3.21"
"CU_DB_Linux_MySQL_B_6.3.3"
"CU_DB_Linux_MySQL_B_6.3.4"
"CU_DB_Linux_MySQL_B_6.3.5"
"CU_DB_Linux_MySQL_B_6.3.6"
"CU_DB_Linux_MySQL_B_6.3.7"
"CU_DB_Linux_MySQL_B_6.3.8"
"CU_DB_Linux_MySQL_B_6.3.9"
)
start_array=(
1
7
13
19
25
31
37
43
49
55
61
67
73
79
85
91
98
107
115
121
127
)
end_array=(
6
12
18
24
30
36
42
48
54
60
66
72
78
84
90
97
106
114
120
126
132
)
outfile='DB_Linux_MySQL_'$1_`date "+%Y-%m-%d_%H_%M_%S"`'.dat'
scriptfile='DB_Linux_MySQL_'$1_`date "+%Y-%m-%d_%H_%M_%S"`''
tabs=1
tabsstr=""

put_head(){
	echo '<?'${1}'?>' | base64 >> $outfile
}

tag_start(){
	echo '<'${1}'>' | base64 >> $outfile
}

tag_end(){
	echo '</'${1}'>' | base64 >> $outfile
}

tag_value(){
	str=""
	str=${1}' ip="'${2}'"/'
	echo '<'$str'>' | base64 >> $outfile
}

tag_equipment(){
	str=""
	str=${1}' type="'${2}'" template="'${3}'" ip="'${4}'" role="'${5}'" connect="yes" '
	echo '<'$str'>' | base64 >> $outfile
}

tag_checkitem(){
	str=""
	str=${1}' type="'${2}'" id="'${3}'" collect="yes" '
	echo '<'$str'>' | base64 >> $outfile
}

tag_checkitem_end(){
	echo '</'${1}'>' | base64 >> $outfile
}

tag_start 'RESULT'
tag_equipment 'EQUIPMENT' $subtype $template $ipaddr  $role
len=${#id_array[@]}
i=0
while [ $i -lt $len ]
do
	tag_checkitem 'CHECKITEM'  $testtype  ${id_array[$i]}
	sed -n "${start_array[$i]},${end_array[$i]}p" "DB_Linux_MySQL_check" >$scriptfile
	cat "$scriptfile" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' | base64 >>$outfile
	sh "$scriptfile" $InstallHomePath $DatabaseUser $DatabasePwd $DatabasePort | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' | base64 >>$outfile
	tag_checkitem_end 'CHECKITEM'
	let i++
done
tag_end 'EQUIPMENT'
tag_end 'RESULT'
rm -f "$scriptfile"
