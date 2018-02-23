#!/bin/bash

FILE=$1

NODES=(/images/rootfs /images/dtb /images/kernel)

for node in ${NODES[*]}; do
    OFFSET=`fit_info -f $FILE -n $node -p data | sed -rn 's/OFF: (.*)/\1/p'`
    echo "Offset of $node: $OFFSET, alignment error (32): " $((OFFSET % 32))
done
