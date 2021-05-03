#!/bin/bash
exec stdbuf -i0 -o0 -e0 \
timeout 600 \
/bin/bash /service_wrapper2.sh
