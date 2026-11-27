# PayGuard — one-tap deploy page

Deploys PayGuardVault to QDay Aevum Testnet (chain 44005) from the visitor's own wallet. The deployer becomes the vault's permanent owner. Payment token: tUSD8 0x456569838f1d43009A91ebA4263147Afd7233483.

- index.html — the deploy page (self-contained; embeds the compiled bytecode).
- PayGuardVault.sol — the full contract source.

Verify the bytecode: compile PayGuardVault.sol with solc 0.8.24, EVM version shanghai, no external dependencies. The creation bytecode must hash to sha256 75299a6fa83e24e2c09feeb3068dddb304ba19f6946080e525db5caac5d26256. Tests: 8/8 pass.
