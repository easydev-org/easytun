#!/bin/sh
# THE CONTAINER MUST HAVE A DEFAULT ROUTE WITH A GATEWAY.
#
# `TestE2EContainerTakesOverTheDefaultRoute` takes the default route over and puts it back, and it SKIPS
# where there is no gateway to restore faithfully - which the job's skip check would report as "a kernel
# test skipped" without naming the real cause. Docker's default bridge gives that route; this checks it
# rather than inheriting an assumption.
#
# IT READS /proc/net/route BECAUSE THE go IMAGE HAS NO `ip`. The format is one line per route, tab
# separated: destination and gateway are 32-bit hex, little-endian, and a destination of 00000000 is the
# default route. A non-zero gateway column is a gateway.
set -eu
awk 'NR > 1 && $2 == "00000000" { found = 1; if ($3 != "00000000") gw = 1 }
     END {
       if (!found) { print "no default route in this container"; exit 1 }
       if (!gw)    { print "the default route has no gateway"; exit 1 }
       print "the container has a default route with a gateway"
     }' /proc/net/route
