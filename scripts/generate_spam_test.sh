#!/bin/bash

ADDR="2QtmUBygxwmLwxh762QaRzw479CPFgRVBc64maQxywhM"

echo "Generating clustered transactions..."

for i in {1..15}; do
  solana transfer $ADDR 0.000001 \
  --allow-unfunded-recipient \
  --no-wait
done

echo "Done generating transactions."
