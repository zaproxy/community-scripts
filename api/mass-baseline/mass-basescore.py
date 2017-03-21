#!/usr/bin/python

from __future__ import print_function
import os
import sys
import subprocess
import traceback

def parse_results (site, date, is_summary_file, file):
  #print ('Parse results for ' + site)
  last_line = ''
  rra = ''

  with open(sys.argv[1] + '/baseline-results/' + site + '/' + date, 'ro') as f:
    for line in f:
      if line.startswith('LINK: '):
        rra = line[5:].rstrip('\n')
      else:
        last_line = line.rstrip('\n')

    if len(last_line) > 0:
      try:
        #print ('Last line: ' + last_line)
        scores = last_line.split('\t')
        if last_line.startswith('FAIL-NEW:'):
          # Weekly format is: FAIL-NEW: x    FAIL-INPROG: x    WARN-NEW: x    WARN-INPROG: x    INFO: x    IGNORE: x    PASS: x
          fail_new = scores[0].split(': ')[1]
          fail_ip = scores[1].split(': ')[1]
          warn_new = scores[2].split(': ')[1]
          warn_ip = scores[3].split(': ')[1]
          ok = scores[6].split(': ')[1]
          # Just add the new and in progress scores for now..
          fail = str(int(fail_new) + int(fail_ip))
          warn = str(int(warn_new) + int(warn_ip))
        else:
          # Stable format is: FAIL: x    WARN: x    INFO: x    IGNORE: x    PASS: x
          fail = scores[0].split(': ')[1]
          warn = scores[1].split(': ')[1]
          ok = scores[4].split(': ')[1]

        if len(rra) > 0:
          file.write ('| [' + site + '](' + rra + ')')
        else:
          file.write ('| ' + site)
        
        if int(fail) > 0:
          file.write ('| [![Score](https://img.shields.io/badge/baseline-fail%20' + fail + '-red.svg)]')
        elif int (warn) > 0:
          file.write ('| [![Score](https://img.shields.io/badge/baseline-warn%20' + warn + '-yellow.svg)]')
        else:
          file.write ('| [![Score](https://img.shields.io/badge/baseline-pass-green.svg)]')
        file.write ('(baseline-results/' + site + '/' + date +')')

        if is_summary_file:
          file.write ('| ' + warn + ' | ' + fail)
          file.write ('| [' + date + '](Baseline-' + site + '-history) |')
        else:
          file.write ('| ' + ok + ' | ' + warn + ' | ' + fail)
          file.write ('| [' + date + '](baseline-results/' + site + '/' + date +') |')
        file.write ('\n')
      except:
        traceback.print_exc()

def handle_site (name, summary_file):
  #print ('Site: ' + name)
  # Output the history page
  f = open(sys.argv[1] + '/Baseline-' + name + '-history.md','w')
  f.write('## ' + name + '\n\n')
  f.write('| Site | Status | Pass | Warn | Fail | Date | \n')
  f.write('| --- | --- | --- | --- | --- | --- |\n')

  all_files = sorted(os.listdir(sys.argv[1] + '/baseline-results/' + name), reverse=True)
  if len(all_files) > 0:
    parse_results(name, all_files[0], True, summary_file)
    for file in all_files:
      parse_results(name, file, False, f)

  f.write ('\n [Back to summary page](Baseline-summary)\n')
  f.close()


# Should just be one arg, the target directory
if len(sys.argv) != 2:
  print ("Usage " + sys.argv[0] + " directory")
  sys.exit(1)
 

summary_file = open(sys.argv[1] + '/Baseline-Summary.md','w')
# Header
summary_file.write('| Site | Status | Warn | Fail | History | \n')
summary_file.write('| --- | --- | --- | --- | --- |\n')

last_file = ''
last_site = ''
for file in sorted(os.listdir(sys.argv[1] + '/baseline-results')):
  if os.path.isdir(sys.argv[1] + '/baseline-results/' + file):
    handle_site(file, summary_file)

summary_file.close()

