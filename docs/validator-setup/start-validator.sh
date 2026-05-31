#!/bin/bash
export PATH="/home/ubuntu/agave-3.1.8/bin:$PATH"
export RUST_BACKTRACE=1
export RUST_LOG=solana=info
exec agave-validator \
  --identity /home/ubuntu/validator-keypair.json \
  --entrypoint entrypoint.mainnet-beta.solana.com:8001 \
  --entrypoint entrypoint2.mainnet-beta.solana.com:8001 \
  --entrypoint entrypoint3.mainnet-beta.solana.com:8001 \
  --rpc-port 8899 \
  --dynamic-port-range 8000-8025 \
  --gossip-port 8001 \
  --no-voting \
  --private-rpc \
  --rpc-bind-address 127.0.0.1 \
  --wal-recovery-mode skip_any_corrupted_record \
  --vote-account /home/ubuntu/vote-account-keypair.json \
  --log ~/log/agave-validator.log \
  --accounts /mnt/accounts \
  --ledger /mnt/ledger \
  --limit-ledger-size 50000000 \
  --known-validator 7Np41oeYqPefeNQEHSv1UDhYrehxin3NStELsSKCT4K2 \
  --known-validator GdnSyH3YtwcxFvQrVVJMm1JhTS4QVX7MFsX56uJLUfiZ \
  --known-validator DE1bawNcRJB9rVm3buyMVfr4mFejNKTyJb4pnB2LLz9f \
  --known-validator CakcnaRDHka2gXyfbEd2d3xsvkJkqsLw2akB3zsN1D2S \
  --expected-genesis-hash 5eykt4UsFv8P8NJdTREpY1vzqKqZKvdpKuc147dw2N9d
