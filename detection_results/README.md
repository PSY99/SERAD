# MHSL detection results

These files contain the scores for the network alarm comparison and event representation comparison in Appendix E, Tables XVIII and XIX. MHSL-S1 contains 1,722 evaluated alarms, and MHSL-S2 contains 1,612.

Table XVIII compares SERAD, DeepCASE, MuSAR, and SAGE on these alarms. Table XIX compares four SERAD event representations. Both tables use the same full SERAD result.

## Files

| File | Contents |
| --- | --- |
| [seed_metrics.csv](seed_metrics.csv) | 30 results: five conditions, two scenarios, and three training seeds. Each row combines the five test folds for one run. |
| [fold_metrics.csv](fold_metrics.csv) | The 150 test-fold results underlying those runs. |
| [native_metrics.csv](native_metrics.csv) | Four results from the MuSAR and SAGE attack analyses, one per method and scenario. |

## Conditions

The `s1-` and `s2-` prefixes identify the MHSL scenario.

| Condition suffix | Method or representation |
| --- | --- |
| `full` | SERAD with attributes, semantic communities, and LLM descriptions. This is the same full SERAD result in both tables. |
| `DeepCASE` | DeepCASE in the network alarm comparison. |
| `attribute_concat` | Attribute association with concatenated text. |
| `attribute_llm` | Attribute association with LLM descriptions. |
| `community_concat` | Attribute and community association with concatenated text. |
| `MuSAR` | MuSAR attack-chain output mapped to network alarms. |
| `SAGE` | SAGE attack-graph output mapped to network alarms. |

## Metrics and averaging

SERAD and DeepCASE use five folds with partition seed 1234 and training seeds 42, 43, and 44. Within each run, the five test folds are combined before computing the metrics in `seed_metrics.csv`. The tables report the mean attack-class F1 across the three runs. MuSAR and SAGE each contribute one result per scenario, recorded in `native_metrics.csv`.

`n` is the number of evaluated network alarms. `tp`, `fp`, `tn`, and `fn` are the confusion counts with attack as the positive class. `precision`, `recall`, and `f1` describe that class. `accuracy` is the fraction of correct predictions. `weighted_f1` weights the two class F1 scores by their alarm counts.

These files evaluate individual network alarms under the Appendix E protocol. Table IX uses each method's evaluation protocol and reports class-weighted metrics on graph edges for SERAD.

For each seed, summing the five fold confusion counts reproduces its run-level metrics. Compute attack F1 as `2 * tp / (2 * tp + fp + fn)`, then average the three run-level F1 scores to obtain the table value.
