"use strict";
// Node's authenticated encryption implementation; no application code executes here.
const crypto = require("node:crypto");

function decode(value, length) {
  if (typeof value !== "string" || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw new Error("Invalid envelope encoding");
  }
  const bytes = Buffer.from(value, "base64");
  if (bytes.toString("base64") !== value || (length !== undefined && bytes.length !== length)) {
    throw new Error("Invalid envelope length");
  }
  return bytes;
}

function material(master, kind) {
  if (master.length !== 32 || !["commonjs", "linux-elf"].includes(kind)) {
    throw new Error("Invalid key or envelope kind");
  }
  return Buffer.from(crypto.hkdfSync("sha256", master, Buffer.alloc(0),
    Buffer.from("rea-aegis/envelope/v1/" + kind), 32));
}

function decrypt(envelope, master, expectedKind) {
  if (envelope.format !== "rea-aegis/envelope/v1") throw new Error("Invalid envelope format");
  const aad = decode(envelope.aad);
  const metadata = JSON.parse(aad.toString("utf8"));
  if (metadata.format !== envelope.format || metadata.kind !== expectedKind) {
    throw new Error("Envelope purpose mismatch");
  }
  const key = material(master, expectedKind);
  try {
    const decipher = crypto.createDecipheriv("aes-256-gcm", key, decode(envelope.nonce, 12));
    decipher.setAAD(aad);
    decipher.setAuthTag(decode(envelope.tag, 16));
    // Never emit unauthenticated plaintext: final() must succeed first.
    const first = decipher.update(decode(envelope.ciphertext));
    return Buffer.concat([first, decipher.final()]);
  } finally {
    key.fill(0);
  }
}

function encrypt(plaintext, master, metadata) {
  if (metadata.kind === "commonjs") {
    const source = plaintext.toString("utf8").replace(/^\uFEFF/, "").replace(/^#![^\r\n]*(?:\r?\n|$)/, "\n");
    new (require("node:vm").Script)(require("node:module").wrap(source));
  }
  const aad = Buffer.from(JSON.stringify(metadata));
  const nonce = crypto.randomBytes(12);
  const key = material(master, metadata.kind);
  try {
    const cipher = crypto.createCipheriv("aes-256-gcm", key, nonce);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    return {format: "rea-aegis/envelope/v1", aad: aad.toString("base64"),
      nonce: nonce.toString("base64"), tag: cipher.getAuthTag().toString("base64"),
      ciphertext: ciphertext.toString("base64")};
  } finally {
    key.fill(0);
  }
}

module.exports = {decrypt, encrypt};

if (require.main === module) {
  const parts = [];
  let size = 0;
  process.stdin.on("data", part => {
    size += part.length;
    if (size > 48 * 1024 * 1024) process.exit(2);
    parts.push(part);
  });
  process.stdin.on("end", () => {
    let master;
    try {
      const request = JSON.parse(Buffer.concat(parts).toString("utf8"));
      master = decode(request.key, 32);
      if (request.operation === "encrypt") {
        process.stdout.write(JSON.stringify(encrypt(decode(request.plaintext), master, request.metadata)));
      } else if (request.operation === "decrypt") {
        process.stdout.write(decrypt(request.envelope, master, request.kind));
      } else throw new Error("Invalid operation");
    } catch (_) {
      process.stderr.write("Authenticated protection operation failed\n");
      process.exitCode = 2;
    } finally {
      if (master) master.fill(0);
    }
  });
}
