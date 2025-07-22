## ThreatGuard Pro - Logic Bomb Analysis
**File:** test_files/test_suspicious.py | **Line:** 23
**Threat Type:** DESTRUCTIVE_PAYLOAD
**Severity:** CRITICAL_BOMB
**Rule ID:** LOGIC_BOMB_DESTRUCTIVE_PAYLOAD
**Message:** File destruction
**Threat Level:** EXTREME
**Trigger Analysis:** Conditional trigger detected for DESTRUCTIVE_PAYLOAD
**Payload Analysis:** Potential DESTRUCTIVE_PAYLOAD payload detected
**Code Snippet:**
```
shutil.rmtree('/important_data')
```
**Neutralization Guide:** URGENT: Destructive Payload detected - Potential DESTRUCTIVE_PAYLOAD payload detected
