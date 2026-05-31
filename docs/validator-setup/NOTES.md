# Mainnet Validator Setup Notes
# From Ramya's setup — needed for Week 4+ when connecting to real network

## Requirements for mainnet validator
- Cloud server (EC2 r6i.2xlarge or better)
- 256GB+ RAM
- 2TB+ NVMe SSD (separate volumes for accounts + ledger)
- Public IP (static)
- Ports open: 8899 (RPC), 8001 (gossip), 8000-8025 (dynamic)

## Your details
- Public IP: 103.232.241.147
- Local IP:  172.27.80.41
- WSL cannot run mainnet validator (NAT, no persistent ports)

## When to use
- Week 4: network_monitor.py connects to devnet/mainnet RPC
- Use Helius/QuickNode RPC endpoint instead of running own validator
- Own validator only needed for Week 4 Day 5 integration test

## Install steps (on EC2 when needed)
See all_commands.txt — it is the history output from Ramya's successful install.
Key steps:
  1. Install agave from source: ./scripts/cargo-install-all.sh .
  2. Generate keypairs: solana-keygen new
  3. Mount separate volumes for /mnt/accounts and /mnt/ledger
  4. Run start-validator.sh in tmux

## Sysctl tuning (required for validator performance)
net.core.rmem_max=134217728
net.core.wmem_max=134217728
net.core.netdev_max_backlog=250000
kernel.pid_max=49152
vm.swappiness=30
