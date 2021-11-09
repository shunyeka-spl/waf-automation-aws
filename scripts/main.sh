#!/bin/bash

time ./requests.sh https://waftest2.ccrt.us &

time ./ipset.sh 
echo "ip added in ipset"

fg
# sam build --use-container &&  sam deploy --config-file Y --profile=ssdev-1 --confirm-changeset


# time ./requests.sh https://waftest2.ccrt.us