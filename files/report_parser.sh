#!/bin/bash

# call with ./report_parser.sh <report file>
cat $1 | sed 's/.*\(CVE-[0-9]\+-[0-9]\+\).*/\1/' | grep "CVE-" | sort | uniq | awk '{printf("\"%s\" ", $0)}'
echo
