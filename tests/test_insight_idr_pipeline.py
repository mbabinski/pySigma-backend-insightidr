import pytest
from sigma.collection import SigmaCollection
from sigma.exceptions import SigmaTransformationError
from sigma.pipelines.insight_idr import insight_idr_pipeline
from sigma.backends.insight_idr import InsightIDRBackend

def test_insight_idr_pipeline_simple():
    assert InsightIDRBackend(processing_pipeline=insight_idr_pipeline()).convert(
        SigmaCollection.from_yaml("""
            title: Test
            status: test
            logsource:
                category: process_creation
                product: windows
            detection:
                sel:
                    CommandLine: val1
                    Image: val2
                condition: sel
        """)
    ) == ['process.cmd_line = NOCASE("val1") AND process.exe_path = NOCASE("val2")']

def test_insight_idr_pipeline_unsupported_field_process_start():
    with pytest.raises(SigmaTransformationError, match="The InsightIDR backend does not support the CurrentDirectory, IntegrityLevel, or imphash fields for process start rules."):
        InsightIDRBackend(processing_pipeline=insight_idr_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: process_creation
                    product: windows
                detection:
                    sel:
                        CurrentDirectory|contains: hi
                        IntegrityLevel: hello
                        imphash: blah
                    condition: sel
            """)
        )

def test_insight_idr_pipeline_unsupported_field_dns():
    with pytest.raises(SigmaTransformationError, match="The InsightIDR backend does not support the ProcessID, QueryStatus, QueryResults, or Image fields for DNS events."):
        InsightIDRBackend(processing_pipeline=insight_idr_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: dns
                detection:
                    sel:
                        ProcessId: 1
                    condition: sel
            """)
        )

def test_insight_idr_pipeline_unsupported_field_web_proxy():
    with pytest.raises(SigmaTransformationError, match="The InsightIDR backend does not support the c-uri-extension, c-uri-stem, c-useragent, cs-cookie, cs-referrer, cs-version, or sc-status fields for web proxy events."):
        InsightIDRBackend(processing_pipeline=insight_idr_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: proxy
                detection:
                    sel:
                        c-uri-extension: test
                    condition: sel
            """)
        )

def test_insight_idr_pipeline_unsupported_rule_type():
    with pytest.raises(SigmaTransformationError, match="Rule type not yet supported by the InsightIDR Sigma backend!"):
        InsightIDRBackend(processing_pipeline=insight_idr_pipeline()).convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: novel_category
                detection:
                    sel:
                        field: blah
                    condition: sel
            """)
        )
