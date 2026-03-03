ecac-core/
│
├── Cargo.toml
├── Cargo.lock
├── README.md
├── LICENSE
├── .gitignore
│
├── docs/
│   ├── architecture.md        # System overview, causal model, replay rules
│   ├── policy-model.md        # RBAC/ABAC definition, deny-wins reasoning
│   ├── protocol.md            # Event schema, serialization, signing
│   ├── invariants.tla+        # Optional formal spec for convergence/safety
│   └── evaluation-plan.md     # Metrics, scenarios, results template
│
├── schemas/
│   ├── op.proto               # gRPC/Protobuf for op exchange (if used)
│   └── vc-schema.json         # W3C VC schema for credentials
│
├── crates/
│   ├── core/                  # Deterministic engine
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── op.rs          # op struct: id, parents, hlc, author, sig, payload
│   │   │   ├── dag.rs         # causal graph + topo sort
│   │   │   ├── crdt.rs        # op-based CRDT merge logic
│   │   │   ├── replay.rs      # deny-wins replayer (retroactive pruning)
│   │   │   ├── policy.rs      # Cedar policy bindings, auth epochs
│   │   │   ├── crypto.rs      # ed25519, blake3, VC checks
│   │   │   └── tests/
│   │   │       ├── convergence.rs
│   │   │       ├── revoke_conflict.rs
│   │   │       └── fuzz_cases.rs
│   │   └── Cargo.toml
│   │
│   ├── net/                   # Networking + replication
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── gossip.rs      # libp2p gossipsub/anti-entropy
│   │   │   ├── rpc.rs         # optional tonic RPC interface
│   │   │   ├── transport.rs   # Noise/TLS/QUIC
│   │   │   └── serializer.rs  # canonical CBOR/Protobuf encoding
│   │   └── Cargo.toml
│   │
│   ├── store/                 # Local persistence + audit
│   │   ├── src/
│   │   │   ├── lib.rs
│   │   │   ├── rocks.rs       # RocksDB storage backend
│   │   │   ├── checkpoint.rs  # snapshot + rollback
│   │   │   └── audit.rs       # hash chain / Rekor anchor
│   │   └── Cargo.toml
│   │
│   ├── policy-engine/         # standalone Cedar evaluator (optional)
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── evaluator.rs
│   │   │   └── api.rs
│   │   └── Cargo.toml
│   │
│   ├── cli/                   # interactive test harness
│   │   ├── src/
│   │   │   ├── main.rs
│   │   │   ├── commands.rs
│   │   │   └── simulate.rs    # partition + reconcile scenarios
│   │   └── Cargo.toml
│   │
│   └── ui/                    # (optional) Tauri-based local-first viewer
│       ├── src/
│       │   ├── main.rs
│       │   └── frontend/
│       └── Cargo.toml
│
├── examples/
│   ├── motor_refurbish.rs     # simplified induction motor process
│   ├── offline_edit.rs        # local op + delayed revocation
│   └── multi_peer.rs          # 3-node causal sync example
│
├── tests/
│   ├── convergence.rs
│   ├── policy_safety.rs
│   └── replay_determinism.rs
│
└── tools/
    ├── fuzz/                  # cargo-fuzz harnesses
    ├── modelcheck/            # TLA+/Apalache configs
    └── scripts/
        ├── build.sh
        ├── run-demo.sh
        └── metrics.sh
