---
"@origin89/km43": minor
---

Add `MessageType.WifiScan` and `MessageType.WifiStatus` with their responses, the `wifi status changed` event kind, `CapabilityBit.WifiScanAndJoinStatus`, and the `ScanState`, `ScanRefusal`, `WifiSecurity`, `WifiBand`, `WifiState` and `WifiFailure` enums. A setup client can list the networks the controller's radio hears and read whether it joined the one written, keyed by the network section version. When a controller does not set capability bit 8, keep manual SSID entry.
