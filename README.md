# Dynamic-Graph-based-Attack-Detection-using-Multi-Source-Heterogeneous-Security-Logs-in-ICS


![framework](assets\framework.png)

This repository provides the **public resources** associated with the research paper:  **"Dynamic Graph-Based Attack Detection Using Multi-Source Heterogeneous Security Logs in ICS"**.

We propose a **dynamic graph-based attack detection method** for **multi-source heterogeneous security logs** in **industrial control systems (ICS)**.

In this repository, we provide:

- A description of the **attack scenarios** in our **laboratory-collected dataset**.
- The **shell command parsing method** used in our approach.
- A **port-to-service mapping table** for reference.

## Laboratory-Collected Dataset

- **Download** and unzip the dataset from [Google Drive](https://bit.ly/40WNDcn).

  - The `savestore.csv` file contains **application logs** exported from **Elasticsearch**, including `.bash_history` and `auth.log`.

  - **Raw network traffic** from involved hosts is stored in separate folders.

  - Our dataset includes **two attack scenarios**, each consisting of **ten attack steps**.

- For details on scenario design, attack step descriptions, and corresponding time windows, refer to:
   [📄 Attack Steps Documentation](attack_step.md)

## Shell Command Parsing Rules

We developed a [📌**rule-based shell command parser**](cmd_parse.py) to analyze command-line inputs, extract key entities, and classify commands based on their function and potential security risks.

The **`Parse_cmd` class** is designed to:

- **Extract command type and arguments** from shell command execution.
- **Identify sensitive operations**, such as privilege escalation (`sudo`) and remote execution (`ssh`).
- **Classify commands** into categories like **file operations, networking, system management, and security-related activities**.

## Port-to-Service Mapping Table

The [**Port-to-Service Mapping Table**](port_service.csv) provides a reference for commonly assigned ports and their associated protocols and services. Each row represents a **specific port number**, detailing its assignment across different transport protocols (**TCP, UDP, SCTP, DCCP**) and a brief **description** of its function.

The table structure is as followed:

| Column Name     | Description                                                  |
| --------------- | ------------------------------------------------------------ |
| **Port**        | The assigned port number.                                    |
| **TCP**         | Indicates if the port is assigned for **TCP** communication (`Yes`, `Assigned`, or blank if unassigned). |
| **UDP**         | Indicates if the port is assigned for **UDP** communication. |
| **SCTP**        | Indicates if the port is assigned for **SCTP** communication. |
| **DCCP**        | Indicates if the port is assigned for **DCCP** communication. |
| **Description** | A brief explanation of the port’s function and usage.        |
