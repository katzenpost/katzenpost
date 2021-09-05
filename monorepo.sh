#!/bin/bash
# Greetings, software archeologist!
#
# This is a Single-Use Reorganization Bash (SURB) script.
#
# It is intended to be used once, in september 2021 (😷), to combine 15
# katzenpost repos into a single monorepo and a single go module.
#
# It is preserved in git history for posterity.
#
# This script is intended to be run from a freshly-created repo containing only
# this script and the file repos.txt containing a list of repos to be merged.
#
# This runs go mod tidy to populate the go.mod file for the new top-level
# module, which has the side effect of upgrading everything. At the time of
# writing, this appears to not be a problem, except for bbolt (the move of
# which is handled in this script).

set -ex

baseurl=github.com/katzenpost
newurl=github.com/katzenpost/katzenpost

# repos.txt is a list of the names of repos to be merged.
cat repos.txt |while read r; do
    # every repo is already cloned and exists above the directory where we are
    # running this, which is the repo we're going to merge everything in to.
    git remote add $r ../$r || true
done
git fetch --all

cat repos.txt |while read r; do
    echo "$r"
    git branch -D renamed_${r} || true
    git checkout -b renamed_${r} $r/master && mkdir $r && ls -a|grep -Ev "^$r$"| \
    grep -Ev "^(\.git|\.|\..|repos.txt|monorepo.sh)$"|grep -Ev '^\..+swp$'|while read x; do
        git mv $x $r/$x
    done && git commit -am "monorepo.sh: move contents of old $r repo to subdir"
done

git checkout main
git merge -s ours --allow-unrelated-histories --no-commit \
    $(cat repos.txt|while read r; do echo renamed_$r; done)
cat repos.txt|while read r; do
    git checkout renamed_$r $r
done
git commit -am "monorepo.sh: octopus merge 🐙"


find|grep 'go.mod$'|xargs git rm
find|grep 'go.sum$'|xargs git rm
git commit -am 'monorepo.sh: remove old go.{mod,sum} files'
find|egrep '\.(rst|html|txt|bib|go)$'|xargs perl -pi -e \
    "s{$baseurl/($(cat repos.txt |xargs echo|sed -e 's/ /|/g'))/(blob|tree)/master}{$newurl/"'$2/master/$1};'
find|egrep '\.(rst|html|txt|bib|go)$'|xargs perl -pi -e \
    "s{$baseurl/($(cat repos.txt |xargs echo|sed -e 's/ /|/g'))}{$newurl/"'$1};'
git commit -am 'monorepo.sh: update imports and other URLs'


# bbolt gets moved in this upgrade
find|egrep '\.(rst|go)$'|xargs perl -pi -e \
    's{github.com/coreos/bbolt}{go.etcd.io/bbolt}'
git commit -am 'update bbolt url'


go mod init $newurl
git add go.mod
git commit -am 'monorepo.sh: init new go module'

sudo docker run -v `pwd`:/katzenpost --rm -it golang:buster bash -c 'cd /katzenpost; go mod tidy'
git add go.sum go.mod

git commit -am 'monorepo.sh: go mod tidy'
