#!/bin/bash
 
# <<plan
# 1. Check in how much time WAF is updated
# plan
 
# echo total $# args
 
# IPSET_NAME='test-ip-set-name'
# IPSET_ID='5511edd2-e521-4a31-a20b-7cac41be38e1'
# JSON=$(aws wafv2 get-ip-set --scope=CLOUDFRONT --region=us-east-1 --name ${IPSET_NAME} --id ${IPSET_ID} --profile=ssdev-1)

# IP=$(echo $JSON | jq '.IPSet.Addresses[0]')
# # MY_IP="\"$(curl ifconfig.me)/32\""
# MY_IP="$(curl ifconfig.me)/32"

# echo $MY_IP
# echo $IP


# if [[ "${IP}" -eq  "${MY_IP}"]]; then
#     printf "Your IP is blocked"
# fi
# | jq '.IPSet.Addresses[0]'


# while true
# do
#     STATUS_CODE="$(curl -X GET ${CLOUDFRONT_URL}  -w "%{http_code}" -o /dev/null -s)"
# 	echo "Status $STATUS_CODE"
# 	if [ "${STATUS_CODE}" != 200 ]; then
#         echo NOT 200  
#         echo IP BLOCKED
#         echo Site returned ${STATUS_CODE}
#         exit 0
#     fi
# done 


#!/bin/bash
 
<<plan
time taken by ip to get into waf ip set
plan
 
echo total $# args

IPSET_NAME='IPV4SET'
IPSET_ID='48df0823-098f-4410-bb2a-666bc85741d6'
IP_TO_CHECK="1.1.1.1/32"
IP_TO_CHECK="3.3.3.3/32"
 
echo IP_TO_CHECK = $IP_TO_CHECK
echo IPSET_NAME = $IPSET_NAME
echo IPSET_ID = $IPSET_ID
echo 
 
# if [ -z "$1" ]
#   then
#     printf "Number of requests needed : \n" ; exit 1
# fi

while true
do
    ONE_IP_ADDRESS="$(aws wafv2 get-ip-set --scope=CLOUDFRONT --region=us-east-1 --name ${IPSET_NAME} --id ${IPSET_ID} --output=json |  jq ".IPSet.Addresses[0]" -r)"
    echo ONE_IP_ADDRESS = $ONE_IP_ADDRESS

    if [ "${ONE_IP_ADDRESS}" == "${IP_TO_CHECK}" ]; 
        then
            echo IP ${ONE_IP_ADDRESS} added to waf ip-set
            exit 0
        # else
        #     echo try ${i}
        fi
done