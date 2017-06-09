#!/bin/bash - 
i=0
while read line; do
    # process only non empty lines because of older tshark release
    if [ ! -z "$line" ]; then
        c=$(printf '%s\n%s\n' "$c" "$line")
        i=$((i+1))

        # curl only every X seconds 
        # the better solution is to use logstash or multithreaded client
        if !((i % 2)) &&  !((SECONDS % 10)) && [[ -v c ]]; then
            #printf '%s\n' "$c"
            printf '%s\n' "$c" | curl -o /dev/null --silent -XPUT http://localhost:9200/_bulk --data-binary @- &
            c=
            i=0
        fi
    fi
done

#echo $c
if [[ -v c ]]; then
#    #printf '%s\n' "$c"
    printf '%s\n' "$c" | curl -o /dev/null --silent -XPUT http://localhost:9200/_bulk --data-binary @- &
fi
