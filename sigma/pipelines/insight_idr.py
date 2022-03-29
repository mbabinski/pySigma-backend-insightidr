from sigma.processing.conditions import IncludeFieldCondition, MatchStringCondition, LogsourceCondition
from sigma.processing.pipeline import ProcessingItem, ProcessingPipeline
from sigma.processing.transformations import ChangeLogsourceTransformation, RuleFailureTransformation, DetectionItemFailureTransformation, FieldMappingTransformation
from sigma.pipelines.common import logsource_windows_network_connection,logsource_windows_network_connection_initiated, logsource_windows_process_creation, logsource_windows_dns_query

def logsource_web_proxy() -> LogsourceCondition:
    return LogsourceCondition(
        category="proxy"
    )

def logsource_firewall() -> LogsourceCondition:
    return LogsourceCondition(
        category="firewall"
    )


def insight_idr_pipeline():
    return ProcessingPipeline(
        name="Generic Log Sources to Rapid7 InsightIDR Transformation",
        priority=10,
        items=[
            # Process Creation
            ProcessingItem(
                identifier="insight_idr_process_creation_fieldmapping",
                transformation=FieldMappingTransformation({
                    "ProcessId": "process.pid",
                    "Image": "process.exe_path",
                    "FileVersion": "process.exe_file.version",
                    "Description": "process.exe_file.description",
                    "Product": "process.exe_file.product_name",
                    "Company": "process.exe_file.author",
                    "OriginalFileName": "process.name",
                    "CommandLine": "process.cmd_line",
                    "User": "process.username",
                    "ParentProcessId": "parent_process.pid",
                    "ParentImage": "parent_process.exe_path",
                    "ParentCommandLine": "parent_process.cmd_line",
                    "ParentUser": "parent_process.username",
                    "md5": "process.exe_file.hashes.md5",
                    "sha1": "process.exe_file.hashes.sha1",
                    "sha256": "process.exe_file.hashes.sha256"
                }),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
            ProcessingItem(
                identifier="insight_idr_process_start_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="process_start_event",
                    product="windows"
                ),
                rule_conditions=[
                    logsource_windows_process_creation(),
                ]
            ),
            # Handle unsupported Process Start fields
            ProcessingItem(
                identifier="insight_idr_fail_process_start_fields",
                transformation=DetectionItemFailureTransformation("The InsightIDR backend does not support the CurrentDirectory, IntegrityLevel, or imphash fields for process start rules."),
                detection_item_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "CurrentDirectory",
                            "IntegrityLevel",
                            "imphash",
                            "LogonId"
                        ]
                    )
                ]
            ),

            # DNS Requests
            ProcessingItem(
                identifier="insight_idr_dns_query_fieldmapping",
                transformation=FieldMappingTransformation({
                    "QueryName": "query",
                    "Computer": "asset"
                }),
                rule_conditions=[
                    logsource_windows_dns_query(),
                ]
            ),
            ProcessingItem(
                identifier="insight_idr_dns_query_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="dns",
                    product="windows"
                ),
                rule_conditions=[
                    logsource_windows_dns_query(),
                ]
            ),
            # Handle unsupported DNS query fields
            ProcessingItem(
                identifier="insight_idr_fail_dns_fields",
                transformation=DetectionItemFailureTransformation("The InsightIDR backend does not support the ProcessID, QueryStatus, QueryResults, or Image fields for DNS events."),
                detection_item_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "ProcessId",
                            "QueryStatus",
                            "QueryResults",
                            "Image"
                        ]
                    )
                ]
            ),
            # Web Proxy
            ProcessingItem(
                identifier="insight_idr_web_proxy_fieldmapping",
                transformation=FieldMappingTransformation({
                    "c-uri": "url",
                    "c-uri-query": "url_path",
                    "cs-bytes": "incoming_bytes",
                    "cs-host": "url_host",
                    "cs-method": "http_method",
                    "r-dns": "url_host",
                    "sc-bytes": "outgoing_bytes",
                    "src_ip": "source_ip",
                    "dst_ip": "destination_ip",
                    "c-useragent": "user_agent"
                }),
                rule_conditions=[
                    logsource_web_proxy(),
                ]
            ),
            ProcessingItem(
                identifier="insight_idr_web_proxy_logsource",
                transformation=ChangeLogsourceTransformation(
                    category="web_proxy"
                ),
                rule_conditions=[
                    logsource_web_proxy(),
                ]
            ),
            # Handle unsupported Web Proxy event fields
            ProcessingItem(
                identifier="insight_idr_fail_web_proxy_fields",
                transformation=DetectionItemFailureTransformation("The InsightIDR backend does not support the c-uri-extension, c-uri-stem, cs-cookie, cs-referrer, cs-version, or sc-status fields for web proxy events."),
                detection_item_conditions=[
                    IncludeFieldCondition(
                        fields=[
                            "c-uri-extension",
                            "c-uri-stem",
                            "c-useragent",
                            "cs-referrer",
                            "cs-version",
                            "sc-status"
                        ]
                    )
                ]
            ),
            # Firewall - this is a placeholder. Firewall rules not yet supported :(
            ProcessingItem(
                identifier="insight_idr_firewall_fieldmapping",
                transformation=FieldMappingTransformation({
                    "src_ip": "source_address",
                    "src_port": "source_port",
                    "dst_ip": "destination_address",
                    "dst_port": "destination_port",
                    "username": "user"
                }),
                rule_conditions=[
                    logsource_firewall(),
                ]
            ),

            # Handle unsupported log sources - sadly there are many of these. But there will be fewer soon as more log sources are supported
            # by this backend!
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Antivirus rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="antivirus")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Django application rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(category="application", product="django")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Python application rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(category="application", product="python")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("RPC firewall application rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="rpc_firewall", category="application")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Ruby on Rails application rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(category="application", product="ruby_on_rails")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Spring application rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(category="application", product="spring")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("SQL application rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(category="application", product="sql")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Windows PowerShell rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[
                    LogsourceCondition(product="windows", service="powershell"),
                    LogsourceCondition(product="windows", category="ps_classic_start"),
		    LogsourceCondition(product="windows", service="powershell-classic"),
                    LogsourceCondition(product="windows", category="ps_classic_provider_start"),
                    LogsourceCondition(product="windows", category="ps_module"),
                    LogsourceCondition(product="windows", category="ps_script")
                ],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("AWS CloudTrail rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="aws", service="cloudtrail")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Azure rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[
                    LogsourceCondition(product="azure", service="AzureActivity"),
                    LogsourceCondition(product="azure", service="azure.activitylogs"),
                    LogsourceCondition(product="azure", service="azure.signinlogs"),
                    LogsourceCondition(product="azure", service="azure.auditlogs")
                ],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("GCP audit rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="gcp", service="gcp.audit")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Google workspace admin rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="google_workspace", service="google_workspace.admin")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("M365 rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[
                    LogsourceCondition(category="ThreatManagement", product="m365"),
                    LogsourceCondition(category="ThreatDetection", product="m365"),
                    LogsourceCondition(category="Exchange", product="m365")
                ],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Okta rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="okta", service="okta")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("OneLogin rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="onelogin", service="onelogin.events")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Qualys rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="qualys")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Firewall rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(category="firewall")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Netflow rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="netflow")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Authentication rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(category="authentication")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Linux/Unix rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[
                    LogsourceCondition(product="linux", service="auditd"),
		    LogsourceCondition(product="linux"),
                    LogsourceCondition(product="unix"),
                    LogsourceCondition(product="linux", service="auth"),
                    LogsourceCondition(product="linux", service="sudo"),
                    LogsourceCondition(product="linux", category="file_create"),
                    LogsourceCondition(product="linux", service="modsecurity"),
                    LogsourceCondition(product="linux", category="network_connection"),
                    LogsourceCondition(product="linux", service="clamav"),
                    LogsourceCondition(product="linux", service="syslog"),
                    LogsourceCondition(product="linux", service="sshd"),
                    LogsourceCondition(product="linux", service="guacamole"),
                    LogsourceCondition(product="linux", service="vsftpd"),
                    LogsourceCondition(product="linux", category="process_creation")
                ],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("MacOS rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[
                    LogsourceCondition(category="file_event", product="macos"),
		    LogsourceCondition(category="process_creation", product="macos")
                ],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Cisco AAA rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="cisco", service="aaa", category="accounting")],
                rule_condition_linking=all
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Zeek rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[LogsourceCondition(product="zeek")],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("Web server rules are not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[
                    LogsourceCondition(category="webserver"),
                    LogsourceCondition(product="apache"),
                    LogsourceCondition(product="windows", category="webserver"),
                    LogsourceCondition(product="zoho_manageengine", category="webserver")
                ],
                rule_condition_linking=any
            ),
            ProcessingItem(
                identifier="insight_idr_fail_rule_not_supported",
                transformation=RuleFailureTransformation("This Windows rule type is not yet supported by the InsightIDR Sigma backend."),
                rule_conditions=[
                    #LogsourceCondition(product="windows"),
                    LogsourceCondition(product="windows", service="application"),
                    LogsourceCondition(product="windows", service="applocker"),
                    LogsourceCondition(product="windows", service="bits-client"),
                    LogsourceCondition(product="windows", service="codeintegrity-operational"),
                    LogsourceCondition(product="windows", service="dns-server"),
                    LogsourceCondition(product="windows", service="driver-framework"),
                    LogsourceCondition(product="windows", service="firewall-as"),
                    LogsourceCondition(product="windows", service="ldap_debug"),
                    LogsourceCondition(product="windows", service="msexchange-management"),
                    LogsourceCondition(product="windows", service="ntlm"),
                    LogsourceCondition(product="windows", service="printservice-admin"),
                    LogsourceCondition(product="windows", service="printservice-operational"),
                    LogsourceCondition(product="windows", service="microsoft-servicebus-client"),
                    LogsourceCondition(product="windows", service="smbclient-security"),
                    LogsourceCondition(product="windows", service="system"),
                    LogsourceCondition(product="windows", service="taskscheduler"),
                    LogsourceCondition(product="windows", service="windefend"),
                    LogsourceCondition(product="windows", service="wmi"),
                    LogsourceCondition(product="windows", category="create_remote_thread"),
                    LogsourceCondition(product="windows", category="create_stream_hash"),
                    LogsourceCondition(product="windows", category="process_access"),
                    LogsourceCondition(product="windows", service="security"),
                    LogsourceCondition(product="windows", category="driver_load"),
                    LogsourceCondition(product="windows", category="file_rename"),
                    LogsourceCondition(category="file_delete", product="windows"),
                    LogsourceCondition(product="windows", category="file_event"),
                    LogsourceCondition(category="image_load", product="windows"),
                    LogsourceCondition(category="network_connection", product="windows"),
                    LogsourceCondition(product="windows", category="pipe_created"),
                    LogsourceCondition(product="windows", category="raw_access_thread"),
                    LogsourceCondition(product="windows", category="registry_event"),
                    LogsourceCondition(product="windows", service="sysmon"),
                    LogsourceCondition(product="windows", category="sysmon_error"),
                    LogsourceCondition(product="windows", category="sysmon_status"),
                    LogsourceCondition(product="windows", category="process_tampering"),
                    LogsourceCondition(product="windows", category="wmi_event"),
                    LogsourceCondition(product="windows", category="edr")
                ],
                rule_condition_linking=any
            )
        ]
    )
