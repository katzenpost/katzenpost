#!/bin/sh
cd _build/html
MKDIRS=$(find * -type d | awk '{print "-mkdir " $0}')
sftp -v -P 22001 katzenpost-web@katzenpost.mixnetworks.org << EOF
cd public_html
$MKDIRS
-mput -r *
EOF
