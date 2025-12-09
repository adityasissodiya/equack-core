# ECAC Gateway Demo Walkthrough

This guide walks through demonstrating the ECAC Gateway - a federated IoT data management system with peer-to-peer synchronization.

## Prerequisites

- Rust toolchain installed
- Terminal access
- Web browser

## Quick Start (Single Node)

The simplest way to demo the gateway:

```bash
cd /home/aditya/Downloads/ecac-core

# Clean up any existing database
rm -rf .ecac.db

# Start the server with write access enabled
cargo run -p ecac-cli --features serve -- serve \
  --allow-writes \
  --site-name "My-Gateway"
```

Open your browser to **http://127.0.0.1:8080**

---

## Two-Node P2P Sync Demo

This demonstrates the core value proposition: data written on one node automatically replicates to connected peers.

### Step 1: Start Node A (Terminal 1)

```bash
cd /home/aditya/Downloads/ecac-core

# Clean up old databases
rm -rf site-a.db site-b.db

# Start Node A
cargo run -p ecac-cli --features serve -- serve \
  --listen 127.0.0.1:8081 \
  --db site-a.db \
  --site-name "Site-A" \
  --allow-writes \
  --libp2p-listen /ip4/127.0.0.1/tcp/9001
```

**Note the Peer ID** in the startup output - it looks like:
```
Local peer id: 12D3KooWAAw3UUhLuwZShvS6Hyz4RqLbBWdzQ8z9NxjkRvgE9ET3
```

### Step 2: Start Node B (Terminal 2)

```bash
cd /home/aditya/Downloads/ecac-core

cargo run -p ecac-cli --features serve -- serve \
  --listen 127.0.0.1:8082 \
  --db site-b.db \
  --site-name "Site-B" \
  --allow-writes \
  --libp2p-listen /ip4/127.0.0.1/tcp/9002
```

### Step 3: Connect the Nodes (Terminal 3)

Replace `<NODE_A_PEER_ID>` with the actual peer ID from Node A's startup output:

```bash
curl -X POST http://127.0.0.1:8082/api/node/peers \
  -H "Content-Type: application/json" \
  -d '{"multiaddr": "/ip4/127.0.0.1/tcp/9001/p2p/<NODE_A_PEER_ID>"}'
```

Example with a real peer ID:
```bash
curl -X POST http://127.0.0.1:8082/api/node/peers \
  -H "Content-Type: application/json" \
  -d '{"multiaddr": "/ip4/127.0.0.1/tcp/9001/p2p/12D3KooWAAw3UUhLuwZShvS6Hyz4RqLbBWdzQ8z9NxjkRvgE9ET3"}'
```

### Step 4: Open the Web UIs

Open two browser windows side by side:
- **Site-A**: http://127.0.0.1:8081
- **Site-B**: http://127.0.0.1:8082

---

## UI Walkthrough

### Dashboard Tab
The main dashboard shows:
- **Header**: Site name, peer count, operation count, sync status
- **Sensor Cards**: Visual display of sensor data (empty initially)

### Sensors Tab
Add sensor data to test synchronization:

1. Click the **"Sensors"** tab
2. Click **"Add Sensor"** button
3. Fill in the form:
   - **Object**: `sensor/temp-01`
   - **Field**: `temperature`
   - **Value**: `23.5`
4. Click **"Add"**

In the two-node demo, refresh the other browser window - the data appears automatically!

### State Tab
- Shows all key-value data as formatted JSON
- Displays the current state digest (cryptographic hash)
- Updates in real-time as data changes

### Operations Tab
- Lists all operations in the DAG (Directed Acyclic Graph)
- Shows operation IDs, types, and relationships
- Demonstrates the append-only operation log

### Trust Tab
- Displays trust relationships between actors
- Shows delegation chains and permissions
- Core to ECAC's access control model

### Peers Tab (Networking Demo)
- Lists connected P2P peers
- Shows peer IDs and connection status
- Allows adding new peers manually

---

## API Demo Commands

### Check Node Status
```bash
# Node A
curl -s http://127.0.0.1:8081/api/node | python3 -m json.tool

# Node B
curl -s http://127.0.0.1:8082/api/node | python3 -m json.tool
```

### View Current State
```bash
# Both nodes should show identical state after sync
curl -s http://127.0.0.1:8081/api/state | python3 -m json.tool
curl -s http://127.0.0.1:8082/api/state | python3 -m json.tool
```

### Write Data via API
```bash
# Write to Node A
curl -X POST http://127.0.0.1:8081/api/data \
  -H "Content-Type: application/json" \
  -d '{"object": "sensor/temp-01", "field": "temperature", "value": "25.0"}'

# Write to Node B
curl -X POST http://127.0.0.1:8082/api/data \
  -H "Content-Type: application/json" \
  -d '{"object": "sensor/humidity-01", "field": "humidity", "value": "65.2"}'
```

### Verify Synchronization
```bash
# Wait 2 seconds for sync, then check both nodes have all data
sleep 2

echo "=== Node A State ==="
curl -s http://127.0.0.1:8081/api/state | python3 -m json.tool

echo "=== Node B State ==="
curl -s http://127.0.0.1:8082/api/state | python3 -m json.tool
```

Both nodes should show identical `state_digest` values and contain all sensor data.

### List Operations
```bash
curl -s http://127.0.0.1:8081/api/ops | python3 -m json.tool
```

### Check Connected Peers
```bash
curl -s http://127.0.0.1:8081/api/node/peers | python3 -m json.tool
```

---

## CLI Options Reference

```
cargo run -p ecac-cli --features serve -- serve [OPTIONS]

Options:
  --listen <ADDR>         HTTP listen address [default: 127.0.0.1:8080]
  --db <PATH>             Path to RocksDB database [default: .ecac.db]
  --site-name <NAME>      Human-readable site name for the UI
  --project <ID>          Project ID for gossip topic [default: ecac-demo]
  --allow-writes          Enable write operations via API
  --libp2p-listen <ADDR>  libp2p listen address (e.g., /ip4/0.0.0.0/tcp/9000)
  --bootstrap <ADDRS>     Bootstrap peer addresses (comma-separated)
```

---

## Troubleshooting

### Port Already in Use
```bash
# Find and kill processes using the ports
lsof -i :8080 -i :8081 -i :8082 -i :9001 -i :9002 | grep LISTEN
kill <PID>
```

### Database Locked
```bash
# Remove old database files
rm -rf .ecac.db site-a.db site-b.db
```

### Nodes Not Syncing
1. Verify both nodes use the same `--project` value (default: `ecac-demo`)
2. Check that the peer connection succeeded (look for `"ok": true` response)
3. Ensure libp2p ports (9001, 9002) are not blocked

### Build Errors
```bash
# Clean and rebuild
cargo clean
cargo build -p ecac-cli --features serve
```

---

## Architecture Overview

```
┌─────────────────┐         libp2p          ┌─────────────────┐
│    Site-A       │◄──────────────────────►│    Site-B       │
│  (Raspberry Pi) │      gossipsub +        │   (Laptop)      │
│                 │    request-response     │                 │
│  HTTP :8081     │                         │  HTTP :8082     │
│  P2P  :9001     │                         │  P2P  :9002     │
└─────────────────┘                         └─────────────────┘
        │                                           │
        │ Write sensor data                         │ Write sensor data
        ▼                                           ▼
   ┌─────────┐                                 ┌─────────┐
   │ RocksDB │  ◄── Sync via announcements ──► │ RocksDB │
   │ (DAG)   │                                 │ (DAG)   │
   └─────────┘                                 └─────────┘
```

**Key Components:**
- **CRDT State**: Multi-value registers (MVReg) and OR-Sets for conflict-free merging
- **DAG Storage**: Append-only operation log with cryptographic linking
- **Gossipsub**: Efficient P2P message propagation for announcements
- **Request-Response**: Direct op fetching when peers have data we need

---

## Demo Script (Copy-Paste Ready)

For a quick demo, run these commands in sequence:

```bash
# Terminal 1: Start Node A
cd /home/aditya/Downloads/ecac-core && rm -rf site-a.db site-b.db && \
cargo run -p ecac-cli --features serve -- serve \
  --listen 127.0.0.1:8081 --db site-a.db --site-name "Site-A" \
  --allow-writes --libp2p-listen /ip4/127.0.0.1/tcp/9001
```

```bash
# Terminal 2: Start Node B
cd /home/aditya/Downloads/ecac-core && \
cargo run -p ecac-cli --features serve -- serve \
  --listen 127.0.0.1:8082 --db site-b.db --site-name "Site-B" \
  --allow-writes --libp2p-listen /ip4/127.0.0.1/tcp/9002
```

```bash
# Terminal 3: Connect and test (replace PEER_ID with Node A's actual peer ID)
PEER_ID="12D3KooWAAw3UUhLuwZShvS6Hyz4RqLbBWdzQ8z9NxjkRvgE9ET3"

# Connect nodes
curl -X POST http://127.0.0.1:8082/api/node/peers \
  -H "Content-Type: application/json" \
  -d "{\"multiaddr\": \"/ip4/127.0.0.1/tcp/9001/p2p/$PEER_ID\"}"

# Write data on Node A
curl -X POST http://127.0.0.1:8081/api/data \
  -H "Content-Type: application/json" \
  -d '{"object": "sensor/temp-01", "field": "temperature", "value": "23.5"}'

# Write data on Node B
curl -X POST http://127.0.0.1:8082/api/data \
  -H "Content-Type: application/json" \
  -d '{"object": "sensor/humidity-01", "field": "humidity", "value": "65.2"}'

# Verify sync (both should show identical data)
sleep 2
echo "Node A:" && curl -s http://127.0.0.1:8081/api/state
echo "Node B:" && curl -s http://127.0.0.1:8082/api/state
```

Open browsers to http://127.0.0.1:8081 and http://127.0.0.1:8082 to see the UI.
