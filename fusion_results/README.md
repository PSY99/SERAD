# Event description review records

Each CSV contains descriptions and annotations for the same 462 event candidates from MHSL-S1. A row contains one description, its supporting records, and the recorded review outcome.

## Files

| File | Model identifier recorded in the file |
| --- | --- |
| [Qwen3-30B](annotation_report_qwen3_30b_a3b_instruct_2507.csv) | `qwen3-30b-a3b-instruct-2507` |
| [Qwen3-235B](annotation_report_qwen3_235b_a22b_instruct_2507.csv) | `qwen3-235b-a22b-instruct-2507` |
| [DeepSeek](annotation_report_deepseek_v3_2.csv) | `deepseek-v3.2` |
| [Gemini Pro](annotation_report_gemini_3_pro_preview.csv) | `gemini-3-pro-preview` |
| [Gemini Flash](annotation_report_gemini_2_5_flash.csv) | `gemini-2.5-flash` |
| [GPT-4o](annotation_report_gpt_4o.csv) | `gpt-4o` |

The files retain their recorded model identifiers. These records concern description review. Detection scores and their evaluation protocol are documented separately in [detection_results](../detection_results/README.md).

## Reading the files

Each file begins with 12 lines of summary comments, followed by the CSV header beginning with `group_id`. Skip those comment lines when importing the table into a spreadsheet or CSV reader.

| Columns | Meaning |
| --- | --- |
| `group_id`, `cluster_id` | Identifiers recorded for the event candidate and its semantic community. |
| `src_ip`, `dst_ip`, `timestamp` | Addresses and time recorded for the candidate. |
| `llm_tag`, `llm_model` | Generated description and its recorded model identifier. |
| `num_events` | Number of input records in the candidate. |
| `signatures`, `commands`, `templates` | Semantic attributes supplied for description generation. |
| `event_summaries`, `base_attrs_summary` | Supporting record summaries and basic attributes. |
| `tag_correct` | Whether the description summarizes its supporting records correctly. |
| `correlation_correct` | The recorded assessment of the candidate's member records. |
| `suggested_tag`, `annotator_notes` | Suggested description and explanation recorded during review. |

For the two annotation columns, `1` means correct, `0` means incorrect, and `?` means uncertain. Description accuracy is the number of rows with `tag_correct = 1` divided by the number of reviewed descriptions.
