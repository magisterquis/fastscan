#!/bin/sh
#
# build.sh
# Build a project
# By J. Stuart McMurray
# Created 20160221
# Last Modified 20160625

set -e

PROG=$(basename $(pwd))

for GOOS in windows linux openbsd darwin; do
        for GOARCH in 386 amd64; do
                export GOOS GOARCH
                N="$PROG.$GOOS.$GOARCH"
                # Windows is special...
                if [ "windows" == $GOOS ]; then
                        N=$N.exe
                fi
                go build -o "$N"
                ls -l $N
        done
done

echo Done.
