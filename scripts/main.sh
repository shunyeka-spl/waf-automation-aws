#!/bin/bash

time ./requsts.sh https://d1sq1bazt84inb.cloudfront.net/ &

time ipset.sh 
echo "ip added in ipset"


sam build --use-container &&  sam deploy --config-file Y --profile=ssdev-1 --confirm-changeset