import { registerHooks } from "node:module";
import path from "node:path";
import fs from "node:fs";
import { pathToFileURL, fileURLToPath } from "node:url";

const rootDir = process.cwd();

registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "firebase-admin") {
      try {
        return nextResolve(specifier, context);
      } catch {
        return {
          url: "data:text/javascript,export const apps = []; export function initializeApp() {} export const credential = { applicationDefault: () => ({}) }; export function firestore() { throw new Error('local sandbox fallback'); } export default { apps, initializeApp, credential, firestore };",
          shortCircuit: true,
        };
      }
    }
    if (specifier === "openai") {
      try {
        return nextResolve(specifier, context);
      } catch {
        return {
          url: "data:text/javascript,export default class OpenAI { constructor() {} }",
          shortCircuit: true,
        };
      }
    }
    if (specifier.startsWith("@/")) {
      const rel = specifier.slice(2);
      const base = path.join(rootDir, "src", rel);
      for (const candidate of [base, `${base}.ts`, `${base}.tsx`, path.join(base, "index.ts")]) {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          return { url: pathToFileURL(candidate).href, shortCircuit: true };
        }
      }
    }
    if ((specifier.startsWith("./") || specifier.startsWith("../")) && context.parentURL) {
      const parentDir = path.dirname(fileURLToPath(context.parentURL));
      const base = path.resolve(parentDir, specifier);
      for (const candidate of [base, `${base}.ts`, `${base}.tsx`, path.join(base, "index.ts")]) {
        if (fs.existsSync(candidate) && fs.statSync(candidate).isFile()) {
          return { url: pathToFileURL(candidate).href, shortCircuit: true };
        }
      }
    }
    return nextResolve(specifier, context);
  },
});
