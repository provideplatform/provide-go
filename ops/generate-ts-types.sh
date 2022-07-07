#!/bin/bash

set -o errexit # set -e
set -o nounset # set -u
set -o pipefail
trap die ERR

die() 
{
    echo "Failed at line $BASH_LINENO"; exit 1
}

setup_env()
{
    if hash tygo 2>/dev/null
    then
        echo 'Using tygo' `tygo -v` > /dev/null
    else 
        echo 'Please install tygo at https://github.com/gzuidhof/tygo'
        exit
    fi

    read -p "This assumes provide-types is located under the same parent directory as provide-go. Proceed? (y/n) " PROCEED
    if ! [ "$PROCEED" == "y" ]
    then
        echo "Canceled"
        exit
    fi
}

setup_env

tygo generate --config ops/tygo.yaml