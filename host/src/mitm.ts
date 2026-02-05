import crypto from "node:crypto";
import fs from "node:fs";
import fsp from "node:fs/promises";
import os from "node:os";
import path from "node:path";

import forge from "node-forge";

export type MitmCa = {
  key: forge.pki.rsa.PrivateKey;
  cert: forge.pki.Certificate;
  keyPem: string;
  certPem: string;
};

export function getDefaultMitmCertDir() {
  const cacheBase = process.env.XDG_CACHE_HOME ?? path.join(os.homedir(), ".cache");
  return path.join(cacheBase, "gondolin", "ssl");
}

export function resolveMitmCertDir(mitmCertDir?: string) {
  return mitmCertDir ?? getDefaultMitmCertDir();
}

export async function loadOrCreateMitmCa(mitmDir: string): Promise<MitmCa> {
  await fsp.mkdir(mitmDir, { recursive: true });

  const caKeyPath = path.join(mitmDir, "ca.key");
  const caCertPath = path.join(mitmDir, "ca.crt");

  try {
    const [keyPem, certPem] = await Promise.all([
      fsp.readFile(caKeyPath, "utf8"),
      fsp.readFile(caCertPath, "utf8"),
    ]);
    return {
      key: forge.pki.privateKeyFromPem(keyPem),
      cert: forge.pki.certificateFromPem(certPem),
      keyPem,
      certPem,
    };
  } catch {
    const generated = generateMitmCa();
    await Promise.all([
      fsp.writeFile(caKeyPath, generated.keyPem),
      fsp.writeFile(caCertPath, generated.certPem),
    ]);
    return generated;
  }
}

export function loadOrCreateMitmCaSync(mitmDir: string): MitmCa {
  fs.mkdirSync(mitmDir, { recursive: true });

  const caKeyPath = path.join(mitmDir, "ca.key");
  const caCertPath = path.join(mitmDir, "ca.crt");

  try {
    const keyPem = fs.readFileSync(caKeyPath, "utf8");
    const certPem = fs.readFileSync(caCertPath, "utf8");
    return {
      key: forge.pki.privateKeyFromPem(keyPem),
      cert: forge.pki.certificateFromPem(certPem),
      keyPem,
      certPem,
    };
  } catch {
    const generated = generateMitmCa();
    fs.writeFileSync(caKeyPath, generated.keyPem);
    fs.writeFileSync(caCertPath, generated.certPem);
    return generated;
  }
}

function generateMitmCa(): MitmCa {
  const keys = forge.pki.rsa.generateKeyPair(2048);
  const cert = forge.pki.createCertificate();

  cert.publicKey = keys.publicKey;
  cert.serialNumber = crypto.randomBytes(16).toString("hex");
  const now = new Date(Date.now() - 5 * 60 * 1000);
  cert.validity.notBefore = now;
  cert.validity.notAfter = new Date(now);
  cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + 3650);

  const attrs = [{ name: "commonName", value: "gondolin-mitm-ca" }];
  cert.setSubject(attrs);
  cert.setIssuer(attrs);

  cert.setExtensions([
    { name: "basicConstraints", cA: true, critical: true },
    {
      name: "keyUsage",
      keyCertSign: true,
      cRLSign: true,
      critical: true,
    },
  ]);

  cert.sign(keys.privateKey, forge.md.sha256.create());

  const keyPem = forge.pki.privateKeyToPem(keys.privateKey);
  const certPem = forge.pki.certificateToPem(cert);

  return {
    key: keys.privateKey,
    cert,
    keyPem,
    certPem,
  };
}
