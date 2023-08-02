#!/bin/bash
# Change these for your environment
git config --global user.email "youremail@example.com"
git config --global user.name "Your name"
user="YourUser"
repo="YourRepo"

# You will also need to set the $baselinecreds envvar if you want to write to your repo's wiki 

if [[ $baselinecreds ]]; then
  git clone https://$baselinecreds@github.com/$user/$repo.wiki
fi

# Format:
# ./mass-basewrapper.sh <results-dir> <target> <path> <link> [<zap-options>]
# The target is assumed to be https and the path can be just /
# The link can be any relevant link (eg to a bug tracker) or / if not needed

# Replace these with your target URLs - these example ones will fail!
./mass-basewrapper.sh $repo.wiki www.fail.example.com / https://www.example.com
./mass-basewrapper.sh $repo.wiki www.pass.example.com / https://www.example.com
./mass-basewrapper.sh $repo.wiki www.warn.example.com / https://www.example.com

./mass-basescore.py $repo.wiki

if [[ $baselinecreds ]]; then
  cd $repo.wiki
  git add Baseline-* baseline-results/ 
  date=`date +%F`
  git commit -m "Baseline scan for $date"
  git push
else
  echo "Environment variable 'baselinecreds' not set so not attempting to update $repo wiki"
fi
