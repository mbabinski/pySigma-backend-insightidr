# pySigma InsightIDR Backend

**Note**: This repository is now archived. It was transfered to and should now be accessed from it's official home at [SigmaHQ](https://github.com/SigmaHQ/pySigma-backend-insightidr)!

## Overview
This is the Rapid7 [InsightIDR](https://www.rapid7.com/products/insightidr/) backend for [pySigma](https://github.com/SigmaHQ/pySigma), capable of converting Sigma rules into [Log Entry Query Language (LEQL)](https://docs.rapid7.com/insightidr/use-a-search-language) queries compatible with the InsightIDR SIEM. It provides the package `sigma.backends.insight_idr` with the `InsightIDRBackend` class.
Further, it contains the processing pipeline `sigma.pipelines.insight_idr`, which performs field mapping and error handling.

## Rule Support
The InsightIDR backend supports the following log entry/rule types:

* Process start events
* DNS query events
* Web proxy events

## Output Format Support
It supports the following output formats which can be used for log search, custom alerts, dashboards, and reporting:

* **default**: queries output in the InsightIDR "Simple" format* 
* **leql_advanced_search**: queries in the "Advanced" format**
* **leql_detection_definition**: queries matching the LEQL detection rule logic format roughly matching what is shown in the InsightIDR Detection Rules -> Detection Rule -> Rule Logic screen***

*Ideal for use in custom alerts.  
**Ideal for use with [InsightIDR4Py](https://github.com/mbabinski/InsightIDR4Py), a module offering streamlined access to the Rapid7 LogSearch API.  
***Conceptual only - these queries are not usable within the InsightIDR interfaces mentioned above.  

Sigma rules using the Sigma endswith modifier uses a regular expression for pattern matching, as LEQL contains no IENDS-WITH or IENDS-WITH-ANY modifier. 

## Usage example
The following example script demonstrates how you can use the InsightIDR backend to generate advanced LEQL queries for the following Sigma rules:
* [Webshell Detection With Command Line Keywords](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_webshell_detection.yml)
* [Windows Cmd Delete File](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_cmd_delete.yml)
* [Suspicious Rundll32 Activity](https://github.com/SigmaHQ/sigma/blob/master/rules/windows/process_creation/proc_creation_win_susp_rundll32_activity.yml)
```python
# demonstrates basic usage of InsightIDR backend
from sigma.collection import SigmaCollection
from sigma.pipelines.insight_idr import insight_idr_pipeline
from sigma.backends.insight_idr import insight_idr

# create pipeline and backend
idr_pipeline = insight_idr_pipeline()
insight_idr_backend = insight_idr.InsightIDRBackend(idr_pipeline)

# load a ruleset
process_start_rules = [r"C:\SigmaRules\rules\windows\process_creation\proc_creation_win_webshell_detection.yml",
                       r"C:\SigmaRules\rules\windows\process_creation\proc_creation_win_cmd_delete.yml",
                       r"C:\SigmaRules\rules\windows\process_creation\proc_creation_win_susp_rundll32_activity.yml"]
					   
process_start_rule_collection = SigmaCollection.load_ruleset(process_start_rules)

# convert the rules
for rule in process_start_rule_collection.rules:
    print(rule.title + " conversion:")
    print(insight_idr_backend.convert_rule(rule, "leql_advanced_search")[0])
    print("\n")
```

with resulting output:
```
Webshell Detection With Command Line Keywords conversion:
where((parent_process.exe_path=/(.*\\w3wp\.exe$|.*\\php\-cgi\.exe$|.*\\nginx\.exe$|.*\\httpd\.exe$)/i OR parent_process.exe_path ICONTAINS-ANY ["\apache", "\tomcat"]) AND ((process.exe_path=/(.*\\net\.exe$|.*\\net1\.exe$)/i) AND (process.cmd_line ICONTAINS-ANY [" user ", " use ", " group "]) OR process.exe_path=/.*\\ping\.exe$/i AND process.cmd_line ICONTAINS " -n " OR process.cmd_line ICONTAINS-ANY ["&cd&echo", "cd /d "] OR process.exe_path=/.*\\wmic\.exe$/i AND process.cmd_line ICONTAINS " /node:" OR process.exe_path=/(.*\\whoami\.exe$|.*\\systeminfo\.exe$|.*\\quser\.exe$|.*\\ipconfig\.exe$|.*\\pathping\.exe$|.*\\tracert\.exe$|.*\\netstat\.exe$|.*\\schtasks\.exe$|.*\\vssadmin\.exe$|.*\\wevtutil\.exe$|.*\\tasklist\.exe$)/i OR process.cmd_line ICONTAINS-ANY [" Test-NetConnection ", "dir \"]))

Windows Cmd Delete File conversion:
where(process.cmd_line ICONTAINS-ALL ["del ", "/f"] OR process.cmd_line ICONTAINS-ALL ["rmdir", "/s", "/q"])


Suspicious Rundll32 Activity conversion:
where(process.cmd_line ICONTAINS-ALL ["javascript:", ".RegisterXLL"] OR process.cmd_line ICONTAINS-ALL ["url.dll", "OpenURL"] OR process.cmd_line ICONTAINS-ALL ["url.dll", "OpenURLA"] OR process.cmd_line ICONTAINS-ALL ["url.dll", "FileProtocolHandler"] OR process.cmd_line ICONTAINS-ALL ["zipfldr.dll", "RouteTheCall"] OR process.cmd_line ICONTAINS-ALL ["shell32.dll", "Control_RunDLL"] OR process.cmd_line ICONTAINS-ALL ["shell32.dll", "ShellExec_RunDLL"] OR process.cmd_line ICONTAINS-ALL ["mshtml.dll", "PrintHTML"] OR process.cmd_line ICONTAINS-ALL ["advpack.dll", "LaunchINFSection"] OR process.cmd_line ICONTAINS-ALL ["advpack.dll", "RegisterOCX"] OR process.cmd_line ICONTAINS-ALL ["ieadvpack.dll", "LaunchINFSection"] OR process.cmd_line ICONTAINS-ALL ["ieadvpack.dll", "RegisterOCX"] OR process.cmd_line ICONTAINS-ALL ["ieframe.dll", "OpenURL"] OR process.cmd_line ICONTAINS-ALL ["shdocvw.dll", "OpenURL"] OR process.cmd_line ICONTAINS-ALL ["syssetup.dll", "SetupInfObjectInstallAction"] OR process.cmd_line ICONTAINS-ALL ["setupapi.dll", "InstallHinfSection"] OR process.cmd_line ICONTAINS-ALL ["pcwutl.dll", "LaunchApplication"] OR process.cmd_line ICONTAINS-ALL ["dfshim.dll", "ShOpenVerbApplication"])
```

## Limitations and Constraints
This backend is in a preliminary stage, and does not support all Sigma rule types or InsightIDR event sources/logset types. Attempting to convert rule types other than the types listed above will result in an error.

Additionally, certain selection fields listed below are not supported within the following Sigma rule types:

Process start events
* CurrentDirectory
* IntegrityLevel
* imphash
* LogonId

DNS query events
* ProcessId
* QueryStatus
* QueryResults

Web proxy events
* c-uri-extension
* c-uri-stem
* c-useragent
* cs-referrer
* cs-version
* sc-status

Finally, Sigma rules using selection conditions based on aggregate functions like count() are deprecated within pySigma and are not supported.

Note that [sigma-cli](https://github.com/SigmaHQ/sigma-cli) contains swithces, ```--skip-unsupported``` and ```--fail-unsupported``` that allow the user to skip rules that cannot be supported by the backend.

## Authorship and Maintenance
This backend was authored and is currently maintained by [Micah Babinski](https://github.com/mbabinski/) with generous assistance from [Thomas Patzke](https://github.com/thomaspatzke). Suggestions and collaboration are welcomed in any form.
