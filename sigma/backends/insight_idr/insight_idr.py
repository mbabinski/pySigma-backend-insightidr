from sigma.conversion.state import ConversionState
from sigma.types import re
from sigma.rule import SigmaRule, SigmaDetection, SigmaDetectionItem
from sigma.conversion.base import TextQueryBackend
from sigma.conversion.deferred import DeferredQueryExpression, DeferredTextQueryExpression
from sigma.conditions import ConditionFieldEqualsValueExpression, ConditionOR, ConditionAND, ConditionSelector
from sigma.modifiers import SigmaModifier, SigmaContainsModifier, SigmaAllModifier
from sigma.types import SigmaCompareExpression, SigmaRegularExpression
from sigma.exceptions import SigmaFeatureNotSupportedByBackendError
from typing import ClassVar, Dict, List, Tuple, Union

class InsightIDRBackend(TextQueryBackend):
    """InsightIDR LEQL backend."""
    group_expression : ClassVar[str] = "({expr})"

    or_token : ClassVar[str] = "OR"
    and_token : ClassVar[str] = "AND"
    not_token : ClassVar[str] = "NOT"
    eq_token : ClassVar[str] = "="

    icontains_token: ClassVar[str] = "ICONTAINS"
    icontains_any_token: ClassVar[str] = "ICONTAINS-ANY"
    icontains_all_token: ClassVar[str] = "ICONTAINS-ALL"

    istarts_with_token: ClassVar[str] = "ISTARTS-WITH"
    istarts_with_any_token: ClassVar[str] = "ISTARTS-WITH-ANY"

    str_quote : ClassVar[str] = '"'
    escape_char : ClassVar[str] = "\\"
    wildcard_multi : ClassVar[str] = "*"
    wildcard_single : ClassVar[str] = "*"

    re_expression : ClassVar[str] = "{field}=/{regex}/i"
    re_escape_char : ClassVar[str] = "\\"
    re_escape : ClassVar[Tuple[str]] = ('"')

    cidr_expression : ClassVar[str] = "IP({value})"

    compare_op_expression : ClassVar[str] = "{field} {operator} {value}"
    compare_operators : ClassVar[Dict[SigmaCompareExpression.CompareOperators, str]] = {
        SigmaCompareExpression.CompareOperators.LT  : "<",
        SigmaCompareExpression.CompareOperators.LTE : "<=",
        SigmaCompareExpression.CompareOperators.GT  : ">",
        SigmaCompareExpression.CompareOperators.GTE : ">=",
    }

    field_null_expression : ClassVar[str] = '{field} = ""'

    field_in_list_expression : ClassVar[str] = "{field} IIN [{list}]"
    list_separator : ClassVar[str] = ", "

    unbound_value_str_expression : ClassVar[str] = '"{value}"'
    unbound_value_num_expression : ClassVar[str] = '{value}'
    unbound_value_re_expression : ClassVar[str] = '{value}'
    no_case_str_expression: ClassVar[str] = "NOCASE({value})"

    def convert_condition_field_eq_val_re(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field matches regular expression value expressions."""
        return self.re_expression.format(
            field=cond.field,
            regex=cond.value.regexp
        )

    def basic_join_or(self, cond, state):
        """Default conversion of OR conditions"""
        if self.token_separator == self.or_token:   # don't repeat the same thing triple times if separator equals or token
            joiner = self.or_token
        else:
            joiner = self.token_separator + self.or_token + self.token_separator

        result = joiner.join((
                converted
                for converted in (
                    self.convert_condition(arg, state) if self.compare_precedence(ConditionOR, arg.__class__)
                    else self.convert_condition_group(arg, state)
                    for arg in cond.args
                )
                if converted is not None and not isinstance(converted, DeferredQueryExpression)
            ))
        return result

    def basic_join_and(self, cond, state):
        """Default conversion of AND conditions"""
        if self.token_separator == self.and_token:   # don't repeat the same thing triple times if separator equals and token
            joiner = self.and_token
        else:
            joiner = self.token_separator + self.and_token + self.token_separator

        result = joiner.join((
                converted
                for converted in (
                    self.convert_condition(arg, state) if self.compare_precedence(ConditionAND, arg.__class__)
                    else self.convert_condition_group(arg, state)
                    for arg in cond.args
                )
                if converted is not None and not isinstance(converted, DeferredQueryExpression)
            ))
        return result
        

    def convert_condition_field_eq_val_str(self, cond : ConditionFieldEqualsValueExpression, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of field = string value expressions"""
        field = cond.field
        val = cond.value.to_plain()
        val_no_wc = val.rstrip("*").lstrip("*")
        # contains
        if val.startswith(self.wildcard_single) and val.endswith(self.wildcard_single):
            result = cond.field + self.token_separator + self.icontains_token + self.token_separator + self.str_quote + val_no_wc + self.str_quote
        # startswith
        elif val.endswith(self.wildcard_single) and not val.startswith(self.wildcard_single):
            result = cond.field + self.token_separator + self.istarts_with_token + self.token_separator + self.str_quote + val_no_wc + self.str_quote
        # endswith
        elif val.startswith(self.wildcard_single) and not val.endswith(self.wildcard_single):
            escaped_val = re.escape(val_no_wc).replace("/", "\\/") # re.escape is not escaping the forward slash correctly :(
            result = self.re_expression.format(field=field, regex=".*{}$".format(escaped_val))
        # plain equals
        else:
            str_val = self.no_case_str_expression.format(value=self.str_quote + self.convert_value_str(cond.value, state) + self.str_quote)
            result = cond.field + self.token_separator + self.eq_token + self.token_separator + str_val

        return result


    def convert_condition_or(self, cond : ConditionOR, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of OR conditions."""
        # child args are both 'field equals value' expressions
        if cond.args[0].__class__.__name__ == "ConditionFieldEqualsValueExpression" and cond.args[1].__class__.__name__ == "ConditionFieldEqualsValueExpression":
            vals = [arg.value.to_plain() for arg in cond.args]
            vals_no_wc = [arg.value.to_plain().rstrip("*").lstrip("*") for arg in cond.args]
            fields = list(set([arg.field for arg in cond.args]))
            # contains-any
            if len(fields) == 1 and vals[0].startswith(self.wildcard_single) and vals[0].endswith(self.wildcard_single):
                result = fields[0] + self.token_separator + self.icontains_any_token + self.token_separator + str(vals_no_wc)
                return result
            # startswith-any
            elif len(fields) == 1 and vals[0].endswith(self.wildcard_single) and not vals[0].startswith(self.wildcard_single):
                result = fields[0] + self.token_separator + self.istarts_with_any_token + self.token_separator + str(vals_no_wc)
                return result
            # endswith-any
            elif len(fields) == 1 and vals[0].startswith(self.wildcard_single) and not vals[0].endswith(self.wildcard_single):
                field = fields[0]
                escaped_vals = [re.escape(val).replace("/", "\\/") for val in vals_no_wc]
                exp = "(.*{}$)".format("$|.*".join(escaped_vals))
                result = self.re_expression.format(field=field, regex=exp)
                return result
            else:
                # 'OR' fields differ
                return self.basic_join_or(cond, state)
        # child args are other 'OR' or 'AND' expressions
        else:
            return self.basic_join_or(cond, state)


    def convert_condition_and(self, cond : ConditionAND, state : ConversionState) -> Union[str, DeferredQueryExpression]:
        """Conversion of AND conditions."""
        # child args are both 'field equals value' expressions
        if cond.args[0].__class__.__name__ == "ConditionFieldEqualsValueExpression" and cond.args[1].__class__.__name__ == "ConditionFieldEqualsValueExpression":
            vals = [arg.value.to_plain() for arg in cond.args]
            vals_no_wc = [arg.value.to_plain().rstrip("*").lstrip("*") for arg in cond.args]
            fields = list(set([arg.field for arg in cond.args]))
            # parent condition has modifiers
            if len(fields) == 1:
                try:
                    # icontains-all
                    if cond.args[0].parent.parent.detection_items[0].modifiers == cond.args[1].parent.parent.detection_items[0].modifiers:
                        if cond.args[0].parent.parent.detection_items[0].modifiers[-1].__name__ == "SigmaAllModifier":
                            result = fields[0] + self.token_separator + self.icontains_all_token + self.token_separator + str(vals_no_wc)
                            return result
                        else:
                            return self.basic_join_and(cond, state)
                    else:
                        return self.basic_join_and(cond, state)
                except:
                    return self.basic_join_and(cond, state)
            else:
                # parent condition does not contain modifiers
                return self.basic_join_and(cond, state)
        # child args are other 'OR' or 'AND' expressions   
        else:
            return self.basic_join_and(cond, state)
        
    def finalize_query(self, rule : SigmaRule, query : Union[str, DeferredQueryExpression], index : int, state : ConversionState, output_format : str) -> Union[str, DeferredQueryExpression]:
        """
        Finalize query by appending deferred query parts to the main conversion result as specified
        with deferred_start and deferred_separator.
        """
        # addition of a check for aggregate functions
        agg_function_strings = ["| count", "| min", "| max", "| avg", "| sum"]
        condition_string = " ".join([item.lower() for item in rule.detection.condition])
        if any(f in condition_string for f in agg_function_strings):
            raise SigmaFeatureNotSupportedByBackendError("Aggregate functions are deprecated and are not supported by the InsightIDR backend.", source=rule.detection.condition)

        # finalize
        if state.has_deferred():
            if isinstance(query, DeferredQueryExpression):
                query = self.deferred_only_query
            return super().finalize_query(rule,
                query + self.deferred_start + self.deferred_separator.join((
                    deferred_expression.finalize_expression()
                    for deferred_expression in state.deferred
                    )
                ),
                index, state, output_format
            )
        else:
            return super().finalize_query(rule, query, index, state, output_format)

    # finalize query for use with log search 'Advanced' option
    def finalize_query_leql_advanced_search(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        return f"""where({query})"""

    # finalize query the way it appears under Detection Rules -> Attacker Behavior Analytics -> Rule Logic
    def finalize_query_leql_detection_definition(self, rule: SigmaRule, query: str, index: int, state: ConversionState) -> str:
        entry_type = rule.logsource.category
        formatted_query = "\n  ".join(re.split("(AND |OR )", query))
        return f"""from(
  entry_type = {entry_type}"
)
where(
  {formatted_query}
)"""
