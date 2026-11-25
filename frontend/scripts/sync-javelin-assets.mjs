#!/usr/bin/env node
import { createHash } from "node:crypto";
import { cp, mkdir, readdir, readFile, rm, stat, writeFile } from "node:fs/promises";
import path from "node:path";
import { fileURLToPath } from "node:url";

const HERE = path.dirname(fileURLToPath(import.meta.url));
const FRONTEND_ROOT = path.resolve(HERE, "..");
const PROJECT_ROOT = path.resolve(FRONTEND_ROOT, "..");
const SOURCE_PUBLIC = path.join(
  PROJECT_ROOT,
  "third_party",
  "Javelin",
  ".opencode",
  "web",
  "dynamic-validation-observatory",
  "public",
);
const LOCK_FILE = path.join(PROJECT_ROOT, "third_party", "javelin.lock.json");
const TARGET_PUBLIC = path.join(FRONTEND_ROOT, "public", "javelin-assets");

async function walkFiles(dir, baseDir = dir) {
  const entries = await readdir(dir, { withFileTypes: true });
  const files = [];
  for (const entry of entries) {
    const absPath = path.join(dir, entry.name);
    if (entry.isDirectory()) {
      files.push(...(await walkFiles(absPath, baseDir)));
    } else if (entry.isFile()) {
      files.push(path.relative(baseDir, absPath).split(path.sep).join("/"));
    }
  }
  return files.sort();
}

async function main() {
  let sourceStat;
  try {
    sourceStat = await stat(SOURCE_PUBLIC);
  } catch {
    sourceStat = null;
  }
  if (!sourceStat || !sourceStat.isDirectory()) {
    throw new Error(
      `Missing Javelin public assets at ${SOURCE_PUBLIC}. Initialize third_party/Javelin submodule first.`,
    );
  }

  let lockMeta = {};
  try {
    lockMeta = JSON.parse(await readFile(LOCK_FILE, "utf8"));
  } catch {
    lockMeta = {};
  }

  await rm(TARGET_PUBLIC, { recursive: true, force: true });
  await mkdir(TARGET_PUBLIC, { recursive: true });
  await cp(SOURCE_PUBLIC, TARGET_PUBLIC, { recursive: true });

  const relativeFiles = await walkFiles(TARGET_PUBLIC);
  const manifestFiles = [];
  for (const relPath of relativeFiles) {
    if (relPath === "asset-manifest.json") continue;
    const content = await readFile(path.join(TARGET_PUBLIC, relPath));
    manifestFiles.push({
      path: relPath,
      size: content.length,
      sha256: createHash("sha256").update(content).digest("hex"),
    });
  }

  const manifest = {
    source: "third_party/Javelin/.opencode/web/dynamic-validation-observatory/public",
    submodule_commit: lockMeta.submodule_commit ?? "",
    javelin_contract_version: lockMeta.javelin_contract_version ?? 1,
    files: manifestFiles,
  };
  await writeFile(
    path.join(TARGET_PUBLIC, "asset-manifest.json"),
    `${JSON.stringify(manifest, null, 2)}\n`,
    "utf8",
  );
}

await main();
