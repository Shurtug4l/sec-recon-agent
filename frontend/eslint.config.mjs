// Flat config for ESLint 9. Bridges eslint-config-next's classic shareable
// configs through FlatCompat (Next 15 still ships them in the legacy format,
// the flat-native rewrite landed upstream but is not the default yet).

import { FlatCompat } from "@eslint/eslintrc";
import path from "node:path";
import { fileURLToPath } from "node:url";

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const compat = new FlatCompat({
  baseDirectory: __dirname,
});

export default [
  {
    // Skip generated and vendored output. ESLint flat config has no global
    // 'ignorePatterns'; an entry with only 'ignores' acts as the global
    // ignore list.
    ignores: [
      ".next/**",
      "node_modules/**",
      "out/**",
      "next-env.d.ts",
      "public/**",
      // ESM config files at the root that export an anonymous object/array
      // by design — naming them would just be noise.
      "eslint.config.mjs",
      "postcss.config.mjs",
    ],
  },
  ...compat.extends("next/core-web-vitals", "next/typescript"),
  {
    rules: {
      // The repo treats unused vars as warnings, not blockers — they are
      // useful signals during refactors but should not fail CI on a stray
      // import in a WIP commit. Underscore prefix opts out entirely (the
      // standard convention for "intentionally unused").
      "@typescript-eslint/no-unused-vars": [
        "warn",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },
];
