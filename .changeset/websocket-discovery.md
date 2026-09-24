---
"@origin89/km43": minor
---

Add `WS_PORT`, `WS_PATH`, `DNSSD_SERVICE` and `DNSSD_TXT_DEVICE_ID`: where a client reaches the WebSocket transport on the site network. Browse for `_km43._tcp`, open `ws://<host>:80/km43`, and run `Discover` on every result before trusting it; a result whose `id` TXT value is not your controller's `device_id` can be skipped.
