# SERAD: Semantic Event Reconstruction for Attack Detection from Multi-Source Lightweight Logs

This repository contains supplementary materials for the SERAD paper, including dataset links, attack scenarios, parsing rules, an event description prompt, and evaluation records.

SERAD links network alarms, application logs, and shell command histories to reconstruct security events. It uses event descriptions and host context for graph-based attack detection.

![SERAD framework](assets/framework.png)

## Materials

| Material | Contents |
| --- | --- |
| [Attack scenarios](attack_step.md) | MHSL attack steps, participating hosts, and recorded time windows. |
| [Description review records](fusion_results/README.md) | Descriptions and review annotations for 462 MHSL-S1 event candidates across six models. |
| [Detection results](detection_results/README.md) | Individual run and fold scores for the MHSL comparisons in Appendix E, Tables XVIII and XIX. |
| [Command parsing rules](cmd_parse.py) | Rules for extracting command types, options, and arguments. |
| [Event description prompt](fusion_prompt.py) | The ICIO prompt template for combining alarm signatures, command information, and log templates. |
| [Network alarm normalization](network_normalization.py) | A field-mapping dictionary and normalization example for network alarms. |
| [Port-to-service mapping](port_service.csv) | Port numbers, transport protocols, and service descriptions. |

## Datasets

### MHSL

MHSL contains two attack scenarios collected in a laboratory network. Each scenario has ten attack steps. The [scenario documentation](attack_step.md) describes the activity and available evidence.

Download the data from [Google Drive](https://drive.google.com/file/d/1y3YEjbWCLlQYDDzUhNwZiWYkPDSPUYav/view). The archive includes `savestore.csv`, which contains records exported from Elasticsearch, including authentication logs and shell command histories. Network traffic captures are stored in host folders.

### Public benchmarks

The paper uses the following public resources for parsing and detection evaluation. The links lead to the dataset authors' repositories or download pages.

| Resource | Use in the paper |
| --- | --- |
| [Loghub](https://github.com/logpai/loghub) | Template extraction on 16 log datasets. |
| [VALB annotations](https://github.com/ginolzh/Variable_Aware_Log_Abstraction) | Variable parameter identification using the original ten categories. |
| [AIT-ADS](https://zenodo.org/records/8263181) and [AIT Log Data Set V2](https://zenodo.org/records/5789064) | Detection on the russellmitchell and santos scenarios. |
| [CIC-IDS2017](https://www.unb.ca/cic/datasets/ids-2017.html) | Detection using network alarms derived from traffic captures. |

## Evaluation records

The [description review files](fusion_results/README.md) contain generated descriptions, supporting records, and annotations for MHSL-S1. Their file guide explains the CSV columns and annotation values.

The [detection result files](detection_results/README.md) support the network alarm and event representation comparisons in Appendix E. They contain 30 results aggregated over folds, 150 individual fold results, and four results from MuSAR and SAGE. The guide explains how to obtain the reported F1 values from the saved confusion counts.

## Parsing and description resources

The `Parse_cmd` class in [cmd_parse.py](cmd_parse.py) extracts command types and arguments, with rules for tools such as `ssh`, `nmap`, and `nc`.

The prompt in [fusion_prompt.py](fusion_prompt.py) follows the Instruction, Context, Input, and Output structure. It combines alarm signatures, command information, and log templates into a short event description.

[network_normalization.py](network_normalization.py) maps alarm fields to a shared schema and normalizes protocols and ports. [port_service.csv](port_service.csv) supplies the associated service information. Its columns are `Port`, `TCP`, `UDP`, `SCTP`, `DCCP`, and `Description`.
