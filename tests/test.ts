import {
  Connection,
  Keypair,
  Transaction,
  sendAndConfirmTransaction,
  ComputeBudgetProgram,
  SystemProgram,
  LAMPORTS_PER_SOL
} from "@solana/web3.js";

async function main() {
  const connection = new Connection(
    "https://api.testnet.solana.com",
    "confirmed"
  );

  const payer = Keypair.generate();
  const receiver = Keypair.generate();

  console.log("Payer:", payer.publicKey.toBase58());
  console.log("Receiver:", receiver.publicKey.toBase58());

  const sig = await connection.requestAirdrop(
    payer.publicKey,
    2 * LAMPORTS_PER_SOL
  );

  await connection.confirmTransaction(sig);

  const tx = new Transaction();

  tx.add(
    ComputeBudgetProgram.setComputeUnitLimit({
      units: 1400000
    })
  );

  tx.add(
    SystemProgram.transfer({
      fromPubkey: payer.publicKey,
      toPubkey: receiver.publicKey,
      lamports: 1000
    })
  );

  const signature = await sendAndConfirmTransaction(
    connection,
    tx,
    [payer]
  );

  console.log("Transaction Signature:");
  console.log(signature);
}

main().catch(console.error);
