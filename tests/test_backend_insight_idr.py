import pytest
from sigma.collection import SigmaCollection
from sigma.pipelines.insight_idr import insight_idr_pipeline
from sigma.backends.insight_idr import InsightIDRBackend

@pytest.fixture
def insight_idr_backend():
    return InsightIDRBackend()

def test_insight_idr_simple_eq_nocase_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field: foo
                    condition: selection
            """)
        ) == ['field = NOCASE("foo")']

def test_insight_idr_simple_contains_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|contains: foo
                    condition: selection
            """)
        ) == ['field ICONTAINS "foo"']

def test_insight_idr_simple_startswith_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|startswith: foo
                    condition: selection
            """)
        ) == ['field ISTARTS-WITH "foo"']

def test_insight_idr_simple_endswith_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|endswith: foo
                    condition: selection
            """)
        ) == ['field=/.*foo$/i']

def test_insight_idr_value_in_list_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field IIN ["val1", "val2", "val3"]']


def test_insight_idr_value_eq_or_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field: val1
                    selection2:
                        field: val2
                    condition: selection or selection2
            """)
        ) == ['field = NOCASE("val1") OR field = NOCASE("val2")']

def test_insight_idr_value_eq_and_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field: val1
                    selection2:
                        field2: val2
                    condition: selection and selection2
            """)
        ) == ['field = NOCASE("val1") AND field2 = NOCASE("val2")']

def test_insight_idr_contains_any_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|contains:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field ICONTAINS-ANY ["val1", "val2", "val3"]']

def test_insight_idr_contains_all_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|contains|all:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field ICONTAINS-ALL ["val1", "val2", "val3"]']

def test_insight_idr_startswith_any_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|startswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ['field ISTARTS-WITH-ANY ["val1", "val2", "val3"]']

def test_insight_idr_endswith_any_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|endswith:
                            - 'val1'
                            - 'val2'
                            - 'val3'
                    condition: selection
            """)
        ) == ["field=/(.*val1$|.*val2$|.*val3$)/i"]

def test_insight_idr_re_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|re: boo.*far
                    condition: selection
            """)
        ) == ["field=/boo.*far/i"]

def test_insight_idr_cidr_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|cidr: 192.168.0.0/16
                    condition: selection
            """)
        ) == ["field = IP(192.168.0.0/16)"]

def test_insight_idr_base64_query(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    selection:
                        field|base64: 'sigma rules!'
                    condition: selection
            """)
        ) == ['field = NOCASE("c2lnbWEgcnVsZXMh")']

def test_insight_idr_condition_nested_logic(insight_idr_backend : InsightIDRBackend):
    assert insight_idr_backend.convert(
            SigmaCollection.from_yaml("""
                title: Test
                status: test
                logsource:
                    category: test_category
                    product: test_product
                detection:
                    sel1:
                        field|contains:
                            - val1
                            - val2
                    sel2a:
                        field|endswith:
                            - val3
                    sel2b:
                        field|contains:
                            - val4
                    condition: sel1 or (sel2a and sel2b)
            """)
        ) == ['field ICONTAINS-ANY ["val1", "val2"] OR field=/.*val3$/i AND field ICONTAINS "val4"']
