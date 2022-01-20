#!/bin/bash
[ $# -ne 1 ] && {
	echo "Usage: sh OS_Linux_check.sh ip";
	exit 1;
}

ipaddr=$1
template='linux_all'
role='全部'
subtype='OS_Linux'
testtype='/操作系统/OS_Linux'

id_array=(
"CU_OS_Linux_B_5.3.1"
"CU_OS_Linux_B_5.3.10_1"
"CU_OS_Linux_B_5.3.10_2"
"CU_OS_Linux_B_5.3.11"
"CU_OS_Linux_B_5.3.12"
"CU_OS_Linux_B_5.3.13"
"CU_OS_Linux_B_5.3.14"
"CU_OS_Linux_B_5.3.15"
"CU_OS_Linux_B_5.3.16_1"
"CU_OS_Linux_B_5.3.16_2"
"CU_OS_Linux_B_5.3.17"
"CU_OS_Linux_B_5.3.18"
"CU_OS_Linux_B_5.3.19"
"CU_OS_Linux_B_5.3.2"
"CU_OS_Linux_B_5.3.20"
"CU_OS_Linux_B_5.3.21"
"CU_OS_Linux_B_5.3.22"
"CU_OS_Linux_B_5.3.23"
"CU_OS_Linux_B_5.3.24"
"CU_OS_Linux_B_5.3.25"
"CU_OS_Linux_B_5.3.26"
"CU_OS_Linux_B_5.3.27"
"CU_OS_Linux_B_5.3.28"
"CU_OS_Linux_B_5.3.29"
"CU_OS_Linux_B_5.3.3"
"CU_OS_Linux_B_5.3.30"
"CU_OS_Linux_B_5.3.31"
"CU_OS_Linux_B_5.3.32"
"CU_OS_Linux_B_5.3.33"
"CU_OS_Linux_B_5.3.4"
"CU_OS_Linux_B_5.3.5"
"CU_OS_Linux_B_5.3.6"
"CU_OS_Linux_B_5.3.7"
"CU_OS_Linux_B_5.3.8"
"CU_OS_Linux_B_5.3.9"
)
start_array=(
1
6
18
32
34
70
72
95
132
160
195
218
224
238
243
246
314
316
323
389
405
446
466
481
483
490
495
497
499
511
513
560
563
586
611
)
end_array=(
5
17
31
33
69
71
94
131
159
194
217
223
237
242
245
313
315
322
388
404
445
465
480
482
489
494
496
498
510
512
559
562
585
610
623
)
outfile='OS_Linux_'$1_`date "+%Y-%m-%d_%H_%M_%S"`'.dat'
scriptfile='OS_Linux_'$1_`date "+%Y-%m-%d_%H_%M_%S"`''
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
	sed -n "${start_array[$i]},${end_array[$i]}p" "OS_Linux_check" >$scriptfile
	cat "$scriptfile" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' | base64 >>$outfile
	sh "$scriptfile" | sed -e 's/&/\&amp;/g' -e 's/</\&lt;/g' -e 's/>/\&gt;/g' | base64 >>$outfile
	tag_checkitem_end 'CHECKITEM'
	let i++
done
tag_end 'EQUIPMENT'
tag_end 'RESULT'
rm -f "$scriptfile"
