// Copies the plugin's incident snapshot into this package before `npm pack` or `npm publish`,
// so the published package carries its own data/incidents.json. `--clean` removes the copy afterwards.
import { copyFileSync, mkdirSync, rmSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const pkg = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const target = resolve(pkg, "data");

if (process.argv.includes("--clean")) {
  rmSync(target, { recursive: true, force: true });
} else {
  mkdirSync(target, { recursive: true });
  copyFileSync(resolve(pkg, "..", "..", "data", "incidents.json"), resolve(target, "incidents.json"));
}
