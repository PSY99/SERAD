# ICIO Prompt Template for Security Behavior Fusion
ICIO_TEMPLATE = """
Instruction:
Generate a concise event tag that summarizes the core security event indicated by the provided log data.
Use the historical tag cache to keep consistent tags for similar behaviors, and refine a tag only when the input differs.

Context:
In security operations, analysts need to correlate network alerts, host logs, and user actions 
to identify potential threats. Heterogeneous logs from different sources (network IDS, system logs, 
bash commands) often describe the same security event from different perspectives. A unified event 
tag helps to:
- Consolidate multi-source event descriptions into a single coherent narrative
- Highlight the core behavior, risk level, and threat nature
- Speed up security response by providing clear, actionable summaries
- Enable efficient attack graph construction and incident investigation

Source confidence guidance:
- Network alert signatures (Signatures) are confirmed IDS detections and carry the HIGHEST confidence.
  Treat them as the primary evidence of the security event.
- Host log templates (Templates) describing authentication events, system operations, etc. are
  reliable host-level observations. When correlated with network alerts, they provide strong
  corroborative evidence that INCREASES the overall confidence of the assessment.
- Command types / commands (Command Types) from bash logs capture specific user operations.
  They may be loosely correlated when IP information is incomplete. Focus on commands that
  are clearly security-relevant (e.g., reconnaissance tools, exploit attempts, lateral movement)
  and avoid giving equal weight to routine administrative commands.

When sources with varying confidence levels are fused together, the tag should:
- Anchor on the highest-confidence evidence (network alerts) to determine the core threat
- Use host-level evidence to enrich the description with specific attack context
  (e.g., what exact operations were performed, which accounts were targeted)
- Avoid diluting the tag with low-relevance details; extract only the most valuable information
  from each source

The event tag should reflect the actual security behavior (e.g., reconnaissance, exploitation, 
lateral movement, data exfiltration) rather than just listing technical details.

Input Data:
Signatures:
{signatures}
Command Types / Commands:
{command_types}
Templates:
{templates}
Historical Tag Cache (semantic -> tag mappings):
{cache_history}

Output Indicator:
Provide a tag that is 10-15 words, accurate to the core event, and event-oriented.
The tag should:
- Focus on security behavior and threat nature (e.g., "reconnaissance", "privilege escalation", "data exfiltration")
- Integrate information from multiple sources when available
- Be specific enough to distinguish different attack stages
- Use security analyst terminology

Example Output:
"Suspicious Internal IP Traffic with Elevated Privilege System Command Execution"
"SSH Brute Force Attack with Multiple Failed Authentication Attempts"
"Network Port Scanning Followed by Vulnerability Exploitation Attempt"
"""
