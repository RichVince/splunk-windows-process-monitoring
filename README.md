# Splunk Windows Process Monitoring & Detection Lab

## Overview
Built and validated a Windows process-monitoring workflow in Splunk using Windows Security Event ID 4688. The project covered process baselining, parent-child analysis, writable-directory hunting, contextual false-positive tuning, dashboard development, and controlled end-to-end validation.

## SOC Workflow
**Collect → Search → Baseline → Filter → Investigate → Detect → Tune → Validate → Report → Dashboard → Document**

## Lab Architecture
- Windows Server 2019 — Splunk Enterprise and Windows endpoint — `192.168.50.10`
- Ubuntu — Linux lab host — `192.168.50.20`
- Kali Linux — security testing host — `192.168.50.30`
- VirtualBox internal network — `192.168.50.0/24`

## Data Source
- Index: `windows`
- Sourcetype: `WinEventLog:Security`
- Primary event: Event ID `4688`
- Key fields: `Account_Name`, `Creator_Process_Name`, `New_Process_Name`, `Process_Command_Line`

## Baseline
```spl
index=windows
| stats count by EventCode
| sort - count
```

```spl
index=windows EventCode=4688
| stats count by New_Process_Name
| sort - count
```

High volume was treated as a baseline observation, not proof of malicious activity.

## Command-Shell Hunt
```spl
index=windows EventCode=4688 New_Process_Name="*\\cmd.exe"
| stats count by Account_Name Creator_Process_Name New_Process_Name Process_Command_Line
| sort - count
```

Expected Splunk-related process noise was filtered so lower-volume activity could be reviewed. One reviewed chain was:

`svchost.exe → cmd.exe → silcollector.cmd configure`

Context supported an assessment consistent with expected system activity.

## Controlled Discovery Activity
A controlled command produced:

`powershell.exe → cmd.exe → whoami.exe`

This demonstrated why a discovery command should trigger contextual review rather than an automatic malicious verdict.

## Writable-Directory Hunt
The detection searched for processes executing from `Users`, `Temp`, and `AppData`. These locations were used as investigative signals, not as stand-alone indicators of compromise.

## Detection Tuning
A temporary `DismHost.exe` instance launched by `cleanmgr.exe` was investigated. Rather than globally excluding `DismHost.exe`, only the validated parent-child relationship was suppressed. This reduced false positives without hiding unrelated executions.

Microsoft Edge update activity from a temporary directory was also investigated. Parent, command-line, account, and timeline context supported a **likely benign / expected update** assessment. Signature verification could not be completed because the temporary file had already disappeared, so that limitation was documented rather than overstated.

## Dashboard
The **Windows Process Security Monitoring** dashboard contained:
1. **Processes Executed from Writable Directories**
2. **Top Processes Executed from Writable Directories**
3. **Top Parent Processes**

Full paths were retained for investigation while executable names were normalized for visualization.

## End-to-End Validation
A controlled test copied `whoami.exe` to:

`C:\Windows\Temp\CyberBoss-Test.exe`

Expected before searching:
- Account: Administrator
- Parent: `powershell.exe`
- Child: `CyberBoss-Test.exe`

Splunk confirmed Event ID 4688 with the expected account, parent, child path, and command line. The event appeared in the detailed panel, the child-process aggregation, and the parent-process aggregation.

**Controlled execution → Event 4688 → Splunk ingestion → detection SPL → dashboard visibility → analyst triage**

After validation, the test file was removed and `Test-Path` returned `False`.

## Key Findings
- Frequency does not equal maliciousness.
- A detection match is not a verdict.
- Parent-child context improves process analysis.
- Writable-directory execution requires contextual triage.
- Known-good behavior should be suppressed narrowly.
- Temporary evidence may disappear; analysts must pivot to remaining telemetry.
- Controlled validation is essential before trusting detection logic.

## Skills Demonstrated
Splunk SPL, Windows Event ID 4688 analysis, process hunting, parent-child analysis, SOC triage, detection development, false-positive tuning, timeline analysis, dashboards, evidence-based classification, and controlled validation.

## Limitations
This was a controlled training environment using Splunk Free, not a production SOC. Production alerting and role-management capabilities were outside the scope of this project.
