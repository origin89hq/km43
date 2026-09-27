---
"@origin89/km43": minor
---

Adds two DC counter kinds, `MetricKind.DC_ENERGY` in Wh and `MetricKind.DC_CHARGE` in tenths of an Ah, and `Validity.Reset` for a counter that went below its previous total. A reading at `Reset` carries its value; start a new run of the series at it rather than drawing a line down to it. `datasetName` takes an optional fifth argument, the `Direction` the counter counts, and `pv-energy-today`, `pv-energy-total` and `consumed-amp-hours` now resolve: the first two for a PV array's or tracker's energy counting out, the last for a battery's charge counting out since the shunt last synchronised. A DC counter looked up without a direction has no word.
