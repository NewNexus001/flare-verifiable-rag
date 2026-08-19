/**
 * jest.config.js — unit test setup (Phase 17, P335-336 / Phase 18, P350-351).
 * Uses Next.js's official next/jest transformer (handles TS + path aliases +
 * SWC), jsdom environment, and the shared setup file.
 */
const nextJest = require("next/jest");

const createJestConfig = nextJest({ dir: "./" });

const customJestConfig = {
  testEnvironment: "jsdom",
  setupFilesAfterEnv: ["<rootDir>/jest.setup.js"],
  // Only the jest suites under src/tests; the Phase 10 crypto suite uses
  // Node's own runner (node --test) and must not be picked up by jest.
  testMatch: ["<rootDir>/src/tests/**/*.test.[jt]s?(x)"],
  testPathIgnorePatterns: ["<rootDir>/node_modules/", "<rootDir>/.next/"],
  moduleNameMapper: {
    // tsconfig path alias (next/jest does not always wire `bundler` resolution)
    "^@/(.*)$": "<rootDir>/src/$1",
    // react-syntax-highlighter ships ESM-first dist; jest resolves the CJS build
    "^react-syntax-highlighter/dist/esm/styles/prism$":
      "react-syntax-highlighter/dist/cjs/styles/prism",
  },
};

module.exports = createJestConfig(customJestConfig);
