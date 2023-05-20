#!/usr/bin/env bash
# this is a very hacky script for figuring out which nodes never appear on a
# successful ping path. we should write something better for this purpose :)
grep OnACK ping.log |cut -d '[' -f 2|cut -f 1 -d ']' |while read sid; do grep -A10 "SURB ID \[$sid" ping.log|grep -Eo '\.$|Hop\[.] [^ ]+'; done|perl -pe 'chomp unless m/\.$/; s/$/\t/ unless m/\.$/'|sort|uniq > goodpaths
grep -A10 "SURB ID " ping.log|grep -Eo '\.$|Hop\[.] [^ ]+'|perl -pe 'chomp unless m/\.$/; s/$/\t/ unless m/\.$/'|sort|uniq >allpaths
cat allpaths |egrep -o '\S+'|sort|uniq > allwords
cat goodpaths |egrep -o '\S+'|sort|uniq > goodwords
diff -u allwords goodwords
