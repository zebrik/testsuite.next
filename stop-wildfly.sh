#!/bin/bash

CONTAINER=hal-wildfly
NETWORK=testnetwork
RUNNING=$(docker inspect --format="{{.State.Running}}" ${CONTAINER} 2> /dev/null)
RESTARTING=$(docker inspect --format="{{.State.Restarting}}" ${CONTAINER} 2> /dev/null)

if [ "$RUNNING" == "true" ] || [ "$RESTARTING" == "true" ]; then
    docker stop ${CONTAINER}
    docker rm ${CONTAINER}
fi

docker network rm ${NETWORK}
