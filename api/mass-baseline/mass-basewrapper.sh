#!/bin/bash
# Parameters:
#	$1	Results directory
#	$2	Target url, eg www.example.com
#	$3	URL path, / or a longer path if required
#	$4	Link, or / if not needed
#	$5+	Params to pass on to zap-baseline.py

date=`date +%F`
mkdir -p "$1/baseline-results/$2"

cmd="./zap-baseline.py -t https://$2$3 -d -c mass-baseline-default.conf \"${@:5} \""

echo $cmd
$cmd > $1/baseline-results/$2/$date

if [ -s $1/baseline-results/$2/$date ]
then
  if [ "$4" != "/" ]
  then
    echo "LINK: $4" >> $1/baseline-results/$2/$date
  fi  
else
  echo "Results file is empty :( $1/baseline-results/$2/$date"
  # Delete it otherwise it will look like everything passed:/
  rm $1/baseline-results/$2/$date
fi

# Ensure ZAP has completely shut down, otherwise it can corrupt the db of the next run
sleep 5 