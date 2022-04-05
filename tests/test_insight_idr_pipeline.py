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

def test_insight_idr_pipeline_unsupported_rule_type():
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

def test_insight_idr_pipeline_unsupported_field():
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
