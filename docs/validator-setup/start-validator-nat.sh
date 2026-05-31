#!/bin/bash
# Use this if behind NAT or firewall
export PATH="/home/ramya/agave-3.1.9/bin:$PATH"
export RUST_BACKTRACE=1
export RUST_LOG=solana=info
exec agave-validator \
  --identity /home/ramya/validator-keypair.json \
  --entrypoint entrypoint.mainnet-beta.solana.com:8001 \
  --entrypoint entrypoint2.mainnet-beta.solana.com:8001 \
  --entrypoint entrypoint3.mainnet-beta.solana.com:8001 \
  --rpc-port 8899 \
  --dynamic-port-range 8000-8025 \
  --gossip-port 8001 \
  --no-voting \
  --rpc-bind-address 0.0.0.0 \
  --enable-rpc-transaction-history \
  --enable-extended-tx-metadata-storage \
  --wal-recovery-mode skip_any_corrupted_record \
  --vote-account /home/ramya/vote-account-keypair.json \
  --log ~/log/agave-validator.log \
  --accounts /home/accounts-data \
  --ledger /home/ledger-data \
  --limit-ledger-size 50000000 \
  --full-rpc-api \
  --gossip-host YOUR_PUBLIC_IP \
  --public-rpc-address YOUR_PUBLIC_IP:8899 \
  --expected-shred-version 50093 \
  --known-validator 7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2 \
  --known-validator GdnSyH3YtwcxFvQrVVJMm1JhTS4QVX7MFsX56uJLUfiZ \
  --known-validator DE1bawNcRJB9rVm3buyMVfr4mFejNKTyJb4pnB2LLz9f \
  --known-validator CakcnaRDHka2gXyfbEd2d3xsvkJkqsLw2akB3zsN1D2S \
  --expected-genesis-hash 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
