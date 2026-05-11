#!/usr/bin/env bash
# inject-partition.sh -- Simulate a network partition by isolating node3
# from node1 and node2 using Linux tc (traffic control) inside the container.
#
# Usage:
#   ./inject-partition.sh [DURATION_SECONDS]
#
# Default partition duration is 30 seconds.

set -euo pipefail

DURATION="${1:-30}"

echo "=== Injecting network partition: isolating node3 for ${DURATION}s ==="

# Resolve the container-internal IPs of node1 and node2 so we can target them.
NODE1_IP=$(docker exec equack-node1 hostname -i | tr -d '[:space:]')
NODE2_IP=$(docker exec equack-node2 hostname -i | tr -d '[:space:]')

echo "  node1 IP: ${NODE1_IP}"
echo "  node2 IP: ${NODE2_IP}"

# Add a prio qdisc on node3's eth0 so we can attach filters.
docker exec equack-node3 tc qdisc add dev eth0 root handle 1: prio bands 3 priomap 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0 0

# Add a netem qdisc with 100% packet loss on band 3.
docker exec equack-node3 tc qdisc add dev eth0 parent 1:3 handle 30: netem loss 100%

# Filter traffic destined for node1 into the lossy band.
docker exec equack-node3 tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 \
  match ip dst "${NODE1_IP}/32" flowid 1:3

# Filter traffic destined for node2 into the lossy band.
docker exec equack-node3 tc filter add dev eth0 protocol ip parent 1:0 prio 1 u32 \
  match ip dst "${NODE2_IP}/32" flowid 1:3

echo "  Partition active -- node3 cannot reach node1 or node2."

echo "  Waiting ${DURATION}s before healing..."
sleep "${DURATION}"

# Heal the partition by removing the root qdisc (removes all children).
docker exec equack-node3 tc qdisc del dev eth0 root

echo "=== Partition healed. node3 can communicate with all peers again. ==="
