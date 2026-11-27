# Changelog

## 0.1.0 — 2026-11-27

- Port of hsm-sim-go's cryptography to .NET 8: key material and MACs, ISO 9564 PIN blocks 0–4, TDES DUKPT, CVV/PVV/IBM 3624, EMV ARQC/ARPC, FF1 and the token vault.
- `HsmClient` for the hsm-sim-go TCP server.
- Parity vectors generated from the Go implementation (`tools/vecgen`), CI interop job running the .NET demo against the Go server.
