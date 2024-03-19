#!/bin/bash
#
# Goal: list all Critical and High vulnerabilities in a FPR
# requires : unzip installed

############################################################
# Help                                                     #
############################################################
Help()
{
   # Display Help
   echo "Present the application name and the number of critical and high vulnerabilities."
   echo "found in the Fortify report file .fpr"
   echo
   echo "Syntax:  [h|filename.fpr]"
   echo "options:"
   echo "h     Print this Help."
   echo "f     filename.fpr - file to be analyzed"
   echo "e     (Optional) Expand the output"
   echo "c     (Optional) Critical|High|Medium|Low - Select a class of vulnerability to show"
   echo
}
expand=0
cat=0
category=""
############################################################
# Process the input options. Add options as needed.        #
############################################################
# Get the options
while getopts ":hec:f:" option; do
   case $option in
      h) # display Help
         Help
         exit;;
      f) # Enter a filename
	       filename=$OPTARG;;
      c) # Check category
         cat=1;
         category=$OPTARG;;
      e) # Expand
      	 expand=1
         :;;
      \?) # Invalid option
	 echo "Error: Invalid option"
	 Help
         exit;;
   esac
done
if [ $# -eq 0 ]; then
    echo "Error: No arguments provided, try -h"
    exit 1
fi

if [[ $expand = 1 && $category != "" ]]; then
  echo "Error: Expand and ByCategory are not compatible with each other."
  exit 1
fi

if [[ $cat = 1 && $category = "" ]]; then
  echo "Error: category not specified"
  exit 1
fi

if [ ! -f "$filename" ]; then
    echo "Error: The file:$filename does not exist. try -h"
    exit 1;
fi


# Present Application Name
#app=`unzip -p $filename audit.fvdl`

app=`unzip -o $filename audit.fvdl > /dev/null`

app_name=`cat audit.fvdl | grep -i "<BuildID>" | cut -d '>' -f 2 | cut -d '<' -f 1`
#echo "$app_name"

n_vulns=`cat audit.fvdl | xmllint --xpath "//*/*[local-name()='Vulnerabilities']" - | grep "<Vulnerability>" | wc -l | xargs`
if (( $expand )); then
	echo "Found $n_vulns vulnerabilities"
elif [[ $expand = 0 && $cat = 0 ]]; then
	echo $n_vulns
fi

# We now have the vulnerabilities references
declare -a vulns

for i in $(seq 1 $n_vulns);
do
  vulns[$i]=`cat audit.fvdl | xmllint --xpath "//*/*[local-name()='Vulnerabilities']/*[$i]/*[local-name()='ClassInfo']/*[local-name()='ClassID']/text()" -`
#uncomment for debug  echo "${vulns[$i]}"
done


declare -a impact
declare -a probability
declare -a status_vuln
declare -i vuln_critical=0;
declare -i vuln_high=0;
declare -i vuln_medium=0;
declare -i vuln_low=0;

for i in $(seq 1 $n_vulns);
do
  impact[$i]=`cat audit.fvdl | xmllint --xpath "//*/*[local-name()='RuleInfo']/*[name()='Rule' and @id='${vulns[$i]}']" - | grep -i "\"impact\"" | cut -d '>' -f 2 | cut -d '<' -f 1 `
  probability[$i]=`cat audit.fvdl | xmllint --xpath "//*/*[local-name()='RuleInfo']/*[name()='Rule' and @id='${vulns[$i]}']" - | grep -i "\"probability\"" | cut -d '>' -f 2 | cut -d '<' -f 1 `
#uncomment for debug  echo "impact ${impact[$i]} and probability ${probability[$i]}"

   if [ "$(echo "${impact[$i]} >= 2.5" | bc) " -eq 1 ] && [ "$(echo "${probability[$i]} >= 2.5" | bc)" -eq 1 ]
   then
     status_vuln[$i]="Critical"
     vuln_critical+=1;
   elif [ "$(echo "${impact[$i]} >= 2.5" | bc) " -eq 1 ] && [ "$(echo "${probability[$i]} <= 2.5" | bc)" -eq 1 ]
   then
     status_vuln[$i]="High"
     vuln_high+=1;
   elif [ "$(echo "${impact[$i]} <= 2.5" | bc)" -eq 1 ] && [ "$(echo "${probability[$i]} >= 2.5" | bc)" -eq 1 ]
   then
     status_vuln[$i]="Medium"
     vuln_medium+=1;
   else
     status_vuln[$i]="Low"
     vuln_low+=1;
   fi
#uncomment for debug   echo ${status_vuln[$i]}
done
# clean up
`rm -f audit.fvdl`

if (( $expand )); then
	echo "The $app_name has $vuln_critical critical vulns and $vuln_high high, ones!"
elif [[ $category != "" ]]; then
	case $category in
 		"Critical") echo $vuln_critical;;
   	"High") echo $vuln_high;;
    "Medium") echo $vuln_medium;;
    "Low") echo $vuln_low;;
	 	\?) exit 1;;
  esac
fi
if [ $vuln_critical -gt 0 ] ||  [ $vuln_high -gt 0 ] 
   then
     if (( $expand )); then
               echo "Pipeline should break!"
           fi
	   exit 1;
   else
     if (( $expand )); then
               echo "Pipeline can go forward!"
	   fi
	   exit 0;
fi


