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
    # 2-gram, with the word " and " in between the words. eg,
    # 'echo foo bar baz|get_pairs' would output these two lines:
    # foo and bar
    # bar and baz
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

get_pairs_with_pos() {
    # this consumes lines of space-separated words and outputs a line for each
    # 2-gram, with the word " and " in between, and prefixed with the word's
    # position. eg, running 'echo foo bar baz|get_pairs_with_pos' would output
    # these two lines:
    # 1:foo and 2:bar
    # 2:bar and 3:baz
    while read line; do
        last=""
        echo "$line" | xargs -n 1 echo | cat -n | perl -pe 's/\t/:/' | while read word; do 
            if [ "$last" != "" ]; then
                echo "$last and $word"
            fi
            last="$word"
        done
    done
}

percent() {
    # this computes a percentage
    echo "$(echo "scale=2; ($1 / $2)*100"|bc|cut -f 1 -d .)%"
}

# this is a list of surb IDs of successful pings
cat ping.log | grep -v mixy | grep OnACK ping.log |cut -d '[' -f 2|cut -f 1 -d ']' > report_goodsurbs.txt

# this is the path of each successful ping, still retaining its surb ID
cat ping.log | grep -v mixy | grep -Eo 'path: .+' > report_surb_and_path.txt

# this is all of the paths (with duplicates)
cat report_surb_and_path.txt | get_path | tee report_all_paths.txt | sort | uniq > report_all_paths_uniq.txt

# this is all of the successful paths (with duplicates)
cat report_goodsurbs.txt| while read surb; do
    grep "$surb" report_surb_and_path.txt
done | tee report_good_surb_and_path.txt | get_path | tee report_good_paths.txt | sort | uniq > report_good_paths_uniq.txt

# these are paths which appeared more than once and were never bad
cat report_surb_and_path.txt report_good_surb_and_path.txt | sort | uniq -d | get_path | sort | uniq -dc | sort -rn > report_always_good_paths_uniq.txt

# these are paths which appeared more than once and were never good
cat report_surb_and_path.txt report_good_surb_and_path.txt | sort | uniq -u | get_path | sort | uniq -dc | sort -rn > report_always_bad_paths_uniq.txt

# this is all of the pairs of nodes found in all paths, with and without duplicates
cat report_all_paths.txt | get_pairs | tee report_all_pairs.txt | sort | uniq > report_all_pairs_uniq.txt

# this is all of the pairs of nodes found in successful paths, with and without duplicates
cat report_good_paths.txt | get_pairs | tee report_good_pairs.txt | sort | uniq > report_good_pairs_uniq.txt

# this is all of the pairs of nodes, with position, found in all paths, with and without duplicates
cat report_all_paths.txt | get_pairs_with_pos | tee report_all_pos_pairs.txt | sort | uniq > report_all_pos_pairs_uniq.txt

# this is all of the pairs of nodes, with position, found in successful paths, with and without duplicates
cat report_good_paths.txt | get_pairs_with_pos | tee report_good_pos_pairs.txt | sort | uniq > report_good_pos_pairs_uniq.txt

# this is all of the names of nodes used, with and without duplicates
cat report_all_paths.txt | egrep -o '\w+' | tee report_all_nodes.txt | sort | uniq > report_all_nodes_uniq.txt

# this is the names of nodes found in successful paths, with and without duplicates
cat report_good_paths.txt | egrep -o '\w+' | tee report_good_nodes.txt | sort | uniq > report_good_nodes_uniq.txt

wc -l ping.log report*txt|sort -rn

num_total=$(cat report_all_paths.txt|wc -l)
num_good=$(cat report_good_paths.txt|wc -l)
num_bad=$(($num_total - $num_good))

echo
echo "==== by node"
cat report_all_nodes_uniq.txt| while read node; do
    n_total="$(grep "$node" report_all_nodes.txt|wc -l)"
    good="$(grep "$node" report_good_nodes.txt|wc -l)"
    bad=$(($n_total - $good))
    echo -e "$(percent $bad $n_total) loss on paths with node $node ${good}+${bad}=${n_total}"
done | sort -n | tee report_bad_nodes.txt

echo
echo "==== by pair of nodes, any position"
cat report_all_pairs_uniq.txt| while read pair; do
    p_total="$(grep "$pair" report_all_pairs.txt|wc -l)"
    good="$(grep "$pair" report_good_pairs.txt|wc -l)"
    bad=$(($p_total - $good))
    echo -e "$(percent $bad $p_total) loss on paths w/ $pair ${good}+${bad}=${p_total}"
done | sort -n | tee report_pair_loss_rate.txt

echo
echo "==== by pair of nodes, with position, sorted by loss"
cat report_all_pos_pairs_uniq.txt| while read pair; do
    p_total="$(grep "$pair" report_all_pos_pairs.txt|wc -l)"
    good="$(grep "$pair" report_good_pos_pairs.txt|wc -l)"
    bad=$(($p_total - $good))
    echo -e "$(percent $bad $p_total) loss on paths with pair $pair ${good}+${bad}=${p_total}\t$(percent $bad $num_bad) of all drops"
done | sort -n | tee report_pos_pair_loss_rate.txt

echo
echo "=== by pair of nodes, with position, sorted by position"
cat report_pos_pair_loss_rate.txt | perl -pe 's/(\S+ loss) on paths with pair (\S+) and (\S+) (.+)/\2 \3\t\1\t\4/'|sort|column -t -s '	'

echo
echo "Sent $num_total, received $num_good dropped $num_bad; $(percent $num_bad $num_total) loss overall."

# in case any node has 100% loss, highlight that at the end (this should generally output nothing)
diff -u report_all_nodes_uniq.txt report_good_nodes_uniq.txt
