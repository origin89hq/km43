---
"@origin89/km43": minor
---

A charger's stage can be reported and named.

- `ChargeStage` names the seven members of enum space `0x0006`: `Off` (1), `Bulk` (2), `Absorption` (3), `Float` (4), `Equalise` (5), `Storage` (6) and `Fault` (7).
- `MetricKind.CHARGE_STAGE` (`0x0704`) is the metric whose value is one of them, and `datasetName` maps it in the live domain to the dataset's `charge-stage`, which `datasetAbsent` no longer lists.

A vendor stage with no member, such as Victron's *starting up*, is published `unnamed_state` with its raw code in a concern (P-164). A client built against the previous version still interoperates: it surfaces the new metric and its values as unrecognised (P-125).
