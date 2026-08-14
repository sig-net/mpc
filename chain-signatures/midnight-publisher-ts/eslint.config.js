import js from "@eslint/js";
import vitest from "@vitest/eslint-plugin";
import prettier from "eslint-config-prettier/flat";
import { defineConfig, globalIgnores } from "eslint/config";
import tseslint from "typescript-eslint";

export default defineConfig([
  globalIgnores(["dist/**", "devtools/real-stack/managed/**"]),

  {
    name: "midnight-publisher/typescript",
    files: ["**/*.ts"],
    extends: [js.configs.recommended, tseslint.configs.recommended],
    languageOptions: {
      parserOptions: {
        projectService: {
          allowDefaultProject: ["devtools/real-stack/*.ts", "vitest.config.ts"],
        },
        tsconfigRootDir: import.meta.dirname,
      },
    },
    linterOptions: {
      reportUnusedDisableDirectives: "error",
    },
    rules: {
      "@typescript-eslint/consistent-type-imports": [
        "error",
        { disallowTypeAnnotations: false, fixStyle: "inline-type-imports" },
      ],
      "@typescript-eslint/no-import-type-side-effects": "error",
      "@typescript-eslint/await-thenable": "error",
      "@typescript-eslint/no-floating-promises": "error",
      "@typescript-eslint/no-misused-promises": "error",
      "@typescript-eslint/no-unused-vars": [
        "error",
        {
          argsIgnorePattern: "^_",
          varsIgnorePattern: "^_",
          caughtErrorsIgnorePattern: "^_",
        },
      ],
    },
  },

  {
    name: "midnight-publisher/tests",
    files: ["tests/**/*.ts", "**/*.test.ts"],
    extends: [vitest.configs.recommended],
    rules: {
      "vitest/no-focused-tests": "error",
      "vitest/expect-expect": ["error", { assertFunctionNames: ["expect", "expectTypeOf"] }],
      // Vitest supports `expect(actual, message)`; the plugin defaults to one argument.
      "vitest/valid-expect": ["error", { maxArgs: 2 }],
    },
  },

  {
    name: "midnight-publisher/config-files",
    files: ["**/*.js", "**/*.mjs"],
    extends: [js.configs.recommended],
  },

  prettier,
]);
