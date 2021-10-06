#!/bin/bash

clear;
REQUESTS=$2
TIME=$3
for (( i=1; i<=REQUESTS; i++ ))
    do 
    echo -n " $i ";
    curl -X GET $1  -w "%{http_code}" -o /dev/null -s;
    echo
    sleep $(( TIME/REQUESTS ));
done