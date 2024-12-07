#! /bin/bash

server_script="server.py"
server_port=50023
server_log="/tmp/tester_server.log"

client_script="client.py"
client_file="client_file.txt"   # NOTE: assumes that the client will write on this file
client_port=40023

tests_summary="baseline-metrics.txt"
base_metrics_tmpfile="/tmp/tester.tmp1"
tested_tmpfile="/tmp/tester.tmp2"
tested_metrics_tmpfile="/tmp/tester.tmp3"

###########
# helpers #
###########

function usage {
	echo "usage: bash $0 [<test_id>]"
	echo -e "ARGS"
	echo -e "\t<test_id>: ID of the test to be run among {A1,A2,A3,B1,B2,B3,C1,C2,C3}. If no ID is specified, all tests are run."
	echo "OPTIONS"
	echo -e "\t-h\tprints this help message."
	exit 0
}

function run_single_test {
  # extract info of the test to run
  testid=$1
  test_metrics=$(cat $tests_summary | awk "BEGIN{toprint=0} /Stats for test/{toprint=0} /Stats for test $testid/{toprint=1} {if(toprint) print}")
  client_cmd=$(echo -e "$test_metrics" | grep "Command" | sed 's/.*python3 //g' | tr -d "]")
  test_metrics=$(echo -e "$test_metrics" | egrep -v "(Stats for test|Command)")
  echo -e "\nTest metrics\n$test_metrics" | egrep "^#" > $base_metrics_tmpfile

  # try to start the client
  echo -e "\nRunning client for test $testid"
  python3 $client_cmd -p $client_port >$tested_tmpfile
  [[ $(echo $?) -gt 0 ]] && echo -e "Cannot to start the client: probably another process is running at port $client_port\nAborting.." && exit 1

  # output comparison between metrics
  echo -e "\nProcessing results"
  [[ -f $tested_metrics_tmpfile ]] && rm $tested_metrics_tmpfile 
  while IFS= read -r line; do
    [[ -z $(echo $line | egrep "^#") ]] && continue
    towrite=$(grep "$(echo $line | sed 's/ -->.*//g')" $tested_tmpfile)
    [[ ! -f $tested_metrics_tmpfile ]] && echo -e "$towrite" > $tested_metrics_tmpfile || echo -e "$towrite" >> $tested_metrics_tmpfile
  done < $base_metrics_tmpfile
  echo -e "Diff between baseline metrics (on the left) and tested solution (on the right)"
  diff -B -y $base_metrics_tmpfile $tested_metrics_tmpfile

  echo -e "\nREMINDER: the number of lines in client file and packets in first window must be exactly the same as the baseline; if this is the case, the other metrics should be lower or equal than the baseline\n"
}

########
# main #
########

test_ids="A1 A2 A3 B1 B2 B3 C1 C2 C3"

# parse options and arguments
while getopts "h" opt; do
  case "$opt" in
  h)
    usage
    exit 0
    ;;
  esac
done
shift $((OPTIND -1))

[[ $# -gt 2 ]] && usage && exit 1
[[ $# -gt 0 ]] && [[ -z $(echo $test_ids | grep "$1") ]] && echo -e "\nERROR: unknown test ID\n" && usage && exit 1
[[ $# -gt 0 ]] && test_ids=$1

# position in the directory of this script
SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
cd $SCRIPT_DIR

# remove previous files (if any)
for file in $client_file $server_log $base_metrics_tmpfile $tested_tmpfile $tested_metrics_tmpfile; do
  [[ -f $file ]] && rm $file
done

# try to start the server
#echo -e "Starting server"
#python3 $server_script -p $server_port 2>&1 >$server_log &
#server_pid=$!

# wait for the server to start
#while [[ $(wc -l $server_log | awk '{print $1}') == "0" ]]; do
#  echo -e "\twaiting for server to start (log has $(wc -l $server_log | awk '{print $1}') #lines).."
#  sleep 1
#done
#[[ -z "$(grep "listening on IP" $server_log)" ]] && echo -e "\nCannot start the server: #probably another process is running at port $server_port\nAborting.." && exit 1
#echo "Server started (PID $server_pid)"

# run tests
for testid in $test_ids; do
  run_single_test $testid
done

# cleanup
kill $server_pid

