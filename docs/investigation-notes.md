# Investigation Notes

## Method
**Collect → Search → Baseline → Filter → Investigate → Detect → Tune → Validate → Report → Dashboard → Document**

## Analyst Principles
- High event volume does not equal malicious activity.
- Detection is not verdict.
- Evaluate path, parent, command line, account, and timeline together.
- Event ID 4688 provides immediate-parent context, not guaranteed complete ancestry.
- Missing temporary artifacts are evidence limitations.
- Suppress known-good behavior as narrowly as practical.

## Notable Investigations
- `whoami.exe`: controlled chain `powershell.exe → cmd.exe → whoami.exe`
- `silcollector`: reviewed `svchost.exe → cmd.exe → silcollector.cmd configure`
- `DismHost.exe`: validated `cleanmgr.exe` parent and tuned only that relationship
- Microsoft Edge Update: contextual evidence supported likely benign update activity; signature verification was unavailable because the temporary file was gone

## Final Validation
Controlled artifact: `C:\Windows\Temp\CyberBoss-Test.exe`

Observed:
- Account: Administrator
- Parent: PowerShell
- Child: `CyberBoss-Test.exe`
- Dashboard visibility: confirmed in all intended views
- Cleanup: `Test-Path` returned `False`

## Conclusion
The project demonstrated a complete defensive workflow from telemetry collection through controlled detection validation.
