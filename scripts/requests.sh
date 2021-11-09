#!/bin/bash
 
<<plan
1 Find real block time of client ip 
2 time taken by ip to get into waf ip set

# How to use this script
# time ./requests.sh  https://d1sq1bazt84inb.cloudfront.net/
plan


echo total $# args

CLOUDFRONT_URL=$1

echo CLOUDFRONT_URL = $CLOUDFRONT_URL

if [ -z "$1" ]
  then
    printf "Add CloudFront URL to test block time" ;
    printf "Example:  time ./requests.sh  https://waftest3.ccrt.us\n";
    exit 1;
fi
# i=0

while true
do
  # (( i++ ))
  STATUS_CODE="$(curl -X GET --header "X-Forwarded-For: 201.158.54.1,233.43.67.1" ${CLOUDFRONT_URL}  -w "%{http_code}" -o /dev/null -s)"
	echo -n "$STATUS_CODE, "
	if [ "${STATUS_CODE}" != 200 ]; then
      echo NOT 200 , IP BLOCKED
      echo Site returned ${STATUS_CODE}
      exit 0
  fi
done
