const { Document, Packer, Paragraph, TextRun } = require("docx");
const fs = require("fs");

const doc = new Document({
  sections: [{
    children: [
      new Paragraph({
        children: [
          new TextRun({
            text: "Solana AI Security Pipeline - Devnet Proof",
            bold: true,
            size: 32
          })
        ]
      }),
      new Paragraph("Report generated successfully.")
    ]
  }]
});

Packer.toBuffer(doc).then(buffer => {
  fs.writeFileSync("./outputs/devnet_proof_report.docx", buffer);
  console.log("Report generated successfully");
});
