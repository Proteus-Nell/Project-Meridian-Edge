// ESLint flat config. Type-aware, because the rules worth having here need type
// information: this client runs several async lanes (the command tail, the
// render lane, the WebSocket receive chain) that mutate shared ratchet and store
// state, so an unawaited promise is a silent correctness bug, not a style nit.
// tsc --noEmit does not catch those; no-floating-promises does.
//
// The compiler already owns unused locals/parameters, strict null handling, and
// exhaustive switches (tsconfig.json), so nothing here duplicates it.

import eslint from "@eslint/js";
import tseslint from "typescript-eslint";

export default tseslint.config(
  {
    // Build output and dependencies are not ours to lint.
    ignores: ["dist/**", "coverage/**", "node_modules/**"],
  },
  eslint.configs.recommended,
  tseslint.configs.recommendedTypeChecked,
  {
    languageOptions: {
      parserOptions: {
        // Resolves each file against tsconfig.json automatically.
        projectService: true,
        tsconfigRootDir: import.meta.dirname,
      },
    },
    rules: {
      // The point of running this at all: a dropped promise loses a ratchet
      // state write or an ack. Requiring an explicit `void` makes "fire and
      // forget" a decision someone wrote down rather than an oversight.
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",

      // Crypto code deals in Uint8Array and branded strings; an accidental
      // `any` erases exactly the guarantees the strict compiler settings buy.
      "@typescript-eslint/no-explicit-any": "error",

      // Deliberate escapes must be visible in review, not silent.
      "@typescript-eslint/no-non-null-assertion": "error",

      // Underscore-prefixed args are an intentional "unused on purpose" marker.
      "@typescript-eslint/no-unused-vars": [
        "error",
        { argsIgnorePattern: "^_", varsIgnorePattern: "^_" },
      ],
    },
  },
  {
    // This config file is not part of the app's tsconfig, so the type-aware
    // rules have no program to resolve it against.
    files: ["**/*.js"],
    extends: [tseslint.configs.disableTypeChecked],
  },
  {
    // Tests reach into internals and assert on loosely typed fixtures, so the
    // template-expression and unsafe-* rules fire constantly with no signal.
    // The correctness rules above still apply here.
    files: ["tests/**"],
    rules: {
      "@typescript-eslint/no-unsafe-assignment": "off",
      "@typescript-eslint/no-unsafe-member-access": "off",
      "@typescript-eslint/no-unsafe-argument": "off",
      "@typescript-eslint/no-unsafe-call": "off",
      "@typescript-eslint/no-unsafe-return": "off",
    },
  },
);
