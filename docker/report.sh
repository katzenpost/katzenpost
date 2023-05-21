#!/usr/bin/env bash
# this is a hacky script for figuring out where the packet loss is.
# we should write something better for this purpose!

# this script excepts a ping.log to exist in the current working directory, and
# will create a lot of report*txt files.

# they are each described in comments below.

# The ping.log file can be created with something like this:
# while true; do time ./ping -c ../../katzen/default_config_without_tor.toml -s echo -n 40 -t 10 -C 40 | tee -a ping.log; sleep 1; done

get_path() {
    # this outputs just the stuff in brackets, eg a %s of a []string
    egrep -o '\[[^]]+\]' | egrep -o '[^][]+'
}

get_pairs() {
    # this consumes lines of space-separated words and outputs a line for each
    # 2-gram. eg, 'echo foo bar baz|get_pairs' would output these two lines:
    # foo bar
    # bar baz
    while read line; do
        last=""
        echo "$line" | xargs -n 1 echo | while read word; do 
            if [ "$last" != "" ]; then
                echo "$last and $word"
            fi
            last="$word"
        done
    done
}

function percent() {
    # this computes a percentage
    echo "scale=2; ($1 / $2)*100"|bc|cut -f 1 -d .
}

# this is a list of surb IDs of successful pings
cat ping.log | grep OnACK ping.log |cut -d '[' -f 2|cut -f 1 -d ']' > report_goodsurbs.txt

# this is the path of each successful ping, still retaining its surb ID
cat ping.log | grep -Eo 'path: .+' > report_surb_and_path.txt

# this is all of the paths (with duplicates)
cat report_surb_and_path.txt | get_path  > report_all_paths.txt

# this is all of the successful paths (with duplicates)
cat report_goodsurbs.txt| while read surb; do
    grep "$surb" report_surb_and_path.txt
done | get_path > report_good_paths.txt

# this is all of the pairs of nodes found in all paths, with and without duplicates
cat report_all_paths.txt | get_pairs > report_all_pairs.txt
cat report_all_pairs.txt | sort | uniq > report_all_pairs_uniq.txt

# this is all of the pairs of nodes found in successful paths, with and without duplicates
cat report_good_paths.txt | get_pairs > report_good_pairs.txt
cat report_good_pairs.txt | sort | uniq > report_good_pairs_uniq.txt

# finally, this is the percentage of paths which include this pair which
# failed. we can't know where the loss actually occurred, but this is the
# maximum packet loss rate that each pair of nodes *could* be responsible for. 
cat report_all_pairs_uniq.txt| while read pair; do
    total="$(grep "$pair" report_all_pairs.txt|wc -l)"
    good="$(grep "$pair" report_good_pairs.txt|wc -l)"
    bad=$(($total - $good))
    echo "$(percent $bad $total) potential packet loss between $pair ($good good, $bad bad, $total total)"
done | sort -n | tee report_bad_pairs.txt

num_total=$(cat report_all_paths.txt|wc -l)
num_good=$(cat report_good_paths.txt|wc -l)
num_bad=$(($num_total - $num_good))

echo "Sent $num_total, received $num_good; $(percent $num_bad $num_total) packet loss overall."

