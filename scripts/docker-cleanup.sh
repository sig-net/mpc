#!/bin/sh

# docker cleanup after tests

echo "Running docker cleanup"

docker_network_cleanup() {
  # Get the list of network names
  for net in $(docker network ls --filter "name=^mpc_it_" --format '{{.Name}}'); do
      # Get container ids for that network
      ids=$(docker ps -aq --filter "network=$net")

      # If containers exist, remove
      if [ -n "$ids" ]; then
          docker rm -f $ids > /dev/null 2>&1
      fi

      # Remove the network
      docker network rm "$net" > /dev/null 2>&1
  done

}

docker_network_cleanup
