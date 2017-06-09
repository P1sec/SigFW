#!/usr/bin/env bash

if [[ $# -ne 1 ]] ; then
    echo "usage: template.sh node"
    exit
fi

curl -XPUT 'http://'$1'/_template/packets-template' -d '
{
    "template": "packets-*",
    "mappings": {
        "_default_": {
            "dynamic": "true",
            "dynamic_date_formats" : [
                "yyyy-MM-dd HH:mm:SS"
            ],
            "dynamic_templates": [
                {
                    "string_fields": {
                        "match": "*",
                        "match_mapping_type": "string",
                        "mapping": {
                            "index": "not_analyzed",
                            "omit_norms": true,
                            "type": "string"
                        }
                    }
                }
            ],
            "properties": {
                "@version": {
                    "type": "string",
                    "index": "not_analyzed"
                }
            }
        },
        "my_mapping": {
            "numeric_detection": true,
            "dynamic": "true",
            "properties": {
                "timestamp": {
                   "type": "date"
                },
                "layers": {
                    "properties": {
                        "tcap": {
                            "properties": {
                                "tcap_opCode_tcap_localValue": {
                                    "type": "integer"
                                }
                            }
                        },
                        "gsm_map": {
                            "properties": {
                                "gsm_old_opCode_gsm_old_localValue": {
                                    "type": "integer"
                                }
                            }
                        }
                    }
                }
            }
        }

    }
}'

echo
