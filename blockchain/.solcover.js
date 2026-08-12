// solidity-coverage configuration (Prompt 118).
//
// IMPORTANT (verified against solidity-coverage 0.8.17 source, 2026-08-10):
// the hardhat plugin builds its API config via `loadSolcoverJS()` in
// plugins/resources/plugin.utils.js, which reads THIS file (or the
// --solcoverjs flag) — the `coverage:` key in hardhat.config.ts is NOT read
// by this plugin version (empirically confirmed: a `coverage: { skipFiles }`
// block in hardhat.config.ts left all 26 interfaces + 2 test helpers in the
// report; the same skipFiles here filters them to zero).
//
// skipFiles entries are PLAIN FOLDER NAMES, not globs: assembleSkipped()
// does path.join(contractsDir, entry) then a raw target.indexOf(folder)===0
// prefix check, so glob characters are kept literally and never match.
//
// Instrumenting the 26 Flare periphery interfaces (huge structs, zero logic
// branches) added no signal and blew the Node heap on Windows (OOM); the 2
// test helpers are excluded the same way. Only VerifiableRAG.sol is measured.
module.exports = {
  skipFiles: ["interfaces", "test"],
};
