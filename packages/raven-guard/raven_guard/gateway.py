"""Fail-closed Policy Gateway and function protection decorators."""

from __future__ import annotations

import functools
import inspect
import re
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from raven_guard.context import get_current_context
from raven_guard.errors import (
    ApprovalRequiredError,
    MalformedArgumentsError,
    PolicyViolationError,
)
from raven_guard.loader import find_default_policy, load_policy
from raven_guard.models import Decision, PolicyDocument, SecurityContext, ToolPolicy
from raven_guard.telemetry import (
    SecurityAuditEvent,
    TelemetryListener,
    emit_security_event,
    register_telemetry_listener,
)

ConditionValidator = Callable[[dict[str, Any], SecurityContext, ToolPolicy], tuple[bool, str]]


class PolicyGateway:
    """Deterministic, fail-closed runtime policy gateway for LLM tool executions.

    Enforces policies compiled by RAVEN's hardening agent or loaded from raven-policy.yaml/json.
    """

    def __init__(
        self,
        policy: str | Path | dict[str, Any] | PolicyDocument | None = None,
        fail_closed: bool = True,
        audit_log_size: int = 1000,
    ) -> None:
        self.fail_closed = fail_closed
        self.audit_log_size = audit_log_size
        self._document: PolicyDocument = PolicyDocument(fail_closed=fail_closed)
        self.decisions: list[dict[str, Any]] = []
        self._custom_conditions: dict[str, ConditionValidator] = {}
        self._policy_path: Path | None = None
        self._last_mtime: float | None = None
        self._reloader: Any = None
        self._reloader_stop_event: Any = None

        if policy is not None:
            self.load(policy)
        else:
            default_path = find_default_policy()
            if default_path:
                self.load(default_path)

    @classmethod
    def from_yaml(cls, path_or_content: str | Path, **kwargs: Any) -> PolicyGateway:
        """Instantiate a PolicyGateway directly from a YAML file path or YAML string."""
        return cls(policy=path_or_content, **kwargs)

    @classmethod
    def from_file(cls, path: str | Path, **kwargs: Any) -> PolicyGateway:
        """Instantiate a PolicyGateway directly from a policy file path."""
        return cls(policy=path, **kwargs)

    @property
    def version(self) -> str:
        return self._document.version

    @property
    def description(self) -> str:
        return self._document.description

    @property
    def tools(self) -> dict[str, ToolPolicy]:
        return self._document.tools

    @property
    def policy_path(self) -> Path | None:
        return self._policy_path

    def load(self, source: str | Path | dict[str, Any] | PolicyDocument) -> None:
        """Loads a policy document from file, string, dictionary, or PolicyDocument."""
        if isinstance(source, (str, Path)):
            p = Path(source)
            if p.is_file():
                self._policy_path = p.resolve()
                try:
                    self._last_mtime = self._policy_path.stat().st_mtime
                except OSError:
                    pass
        doc = load_policy(source)
        self._document = doc
        self.fail_closed = doc.fail_closed

    def reload(self, force: bool = False) -> bool:
        """Reloads the policy document from the configured file path if modified.

        Returns:
            True if policy was successfully reloaded, False if unchanged or no file.
        """
        if self._policy_path is None or not self._policy_path.is_file():
            return False

        try:
            curr_mtime = self._policy_path.stat().st_mtime
            if force or self._last_mtime is None or curr_mtime > self._last_mtime:
                doc = load_policy(self._policy_path)
                self._document = doc
                self.fail_closed = doc.fail_closed
                self._last_mtime = curr_mtime
                return True
        except (OSError, ValueError):
            return False

        return False

    def start_auto_reload(self, interval_seconds: float = 1.0) -> None:
        """Starts a background daemon thread that periodically reloads the policy file."""
        if self._reloader is not None and self._reloader.is_alive():
            return

        import threading

        stop_event = threading.Event()

        def _watch_loop():
            while not stop_event.is_set():
                stop_event.wait(interval_seconds)
                if stop_event.is_set():
                    break
                self.reload()

        self._reloader_stop_event = stop_event
        self._reloader = threading.Thread(
            target=_watch_loop, daemon=True, name="RavenGuardPolicyReloader"
        )
        self._reloader.start()

    def stop_auto_reload(self) -> None:
        """Stops the background auto-reloading thread."""
        if self._reloader_stop_event is not None:
            self._reloader_stop_event.set()
        if self._reloader is not None:
            self._reloader.join(timeout=2.0)
            self._reloader = None
            self._reloader_stop_event = None

    def apply_candidate(self, candidate: dict[str, Any] | ToolPolicy) -> None:
        """Applies a single ToolPolicy or compiled PolicyCandidate dictionary."""
        if isinstance(candidate, ToolPolicy):
            self._document.tools[candidate.tool] = candidate
        elif isinstance(candidate, dict) and "tool" in candidate:
            self._document.tools[candidate["tool"]] = ToolPolicy.from_dict(candidate)
        else:
            raise ValueError(f"Invalid candidate format: {candidate}")

    def clear(self) -> None:
        """Clears all loaded policies and audit logs."""
        self._document = PolicyDocument(fail_closed=self.fail_closed)
        self.decisions.clear()

    def register_condition(self, name: str, validator: ConditionValidator) -> None:
        """Registers a custom condition evaluator."""
        self._custom_conditions[name] = validator

    def add_telemetry_listener(self, listener: TelemetryListener) -> None:
        """Registers a listener for structured security audit events."""
        register_telemetry_listener(listener)

    def authorize(
        self,
        tool: str,
        arguments: dict[str, Any] | None = None,
        context: SecurityContext | dict[str, Any] | None = None,
    ) -> Decision:
        """Evaluates whether a tool call is authorized under the active policy.

        Returns:
            Decision: object with .allowed (bool), .reason (str), and violation details.
        """
        # Malformed arguments check
        if arguments is None:
            args: dict[str, Any] = {}
        elif not isinstance(arguments, dict):
            decision = Decision(
                allowed=False,
                reason="malformed_arguments:not_a_dict",
                tool=tool,
                policy_source="gateway_default",
                violations=["malformed_arguments:not_a_dict"],
            )
            self._record(tool, {}, decision, context)
            return decision
        else:
            args = arguments

        ctx = SecurityContext.from_any(context) if context is not None else (get_current_context() or SecurityContext())

        # Check for invalid numeric amounts in arguments
        if "amount" in args and args["amount"] is not None:
            try:
                amt = float(args["amount"])
                if amt < 0:
                    decision = Decision(
                        allowed=False,
                        reason="malformed_arguments:negative_amount",
                        tool=tool,
                        policy_source="gateway_default",
                        violations=["malformed_arguments:negative_amount"],
                    )
                    self._record(tool, args, decision, ctx)
                    return decision
            except (ValueError, TypeError):
                decision = Decision(
                    allowed=False,
                    reason="malformed_arguments:invalid_amount_type",
                    tool=tool,
                    policy_source="gateway_default",
                    violations=["malformed_arguments:invalid_amount_type"],
                )
                self._record(tool, args, decision, ctx)
                return decision

        policy = self._document.tools.get(tool)

        # Fail closed: no policy for this tool -> deny
        if policy is None:
            allowed = not self.fail_closed
            reason = "allowed_permissive_no_policy" if allowed else f"no_policy_for_tool:{tool}"
            decision = Decision(
                allowed=allowed,
                reason=reason,
                tool=tool,
                policy_source="gateway_default",
                violations=[] if allowed else [reason],
            )
            self._record(tool, args, decision, ctx)
            return decision

        # Role-based privilege check
        if policy.allowed_roles:
            has_role = any(r in policy.allowed_roles for r in ctx.roles)
            if not has_role:
                decision = Decision(
                    allowed=False,
                    reason="insufficient_role_privilege",
                    tool=tool,
                    policy_source="candidate",
                    violations=["insufficient_role_privilege"],
                )
                self._record(tool, args, decision, ctx)
                return decision

        # Cross-field context claims validation (IDOR and Confused Deputy protection)
        if policy.context_claims:
            for arg_name, claim_key in policy.context_claims.items():
                if arg_name in args:
                    claim_val = ctx.get_claim(claim_key)
                    if claim_val is None:
                        decision = Decision(
                            allowed=False,
                            reason=f"missing_context_claim:{claim_key}",
                            tool=tool,
                            policy_source="candidate",
                            violations=[f"missing_context_claim:{claim_key}"],
                        )
                        self._record(tool, args, decision, ctx)
                        return decision
                    if str(args[arg_name]) != str(claim_val):
                        decision = Decision(
                            allowed=False,
                            reason=f"claim_mismatch:{arg_name}!={claim_key}",
                            tool=tool,
                            policy_source="candidate",
                            violations=[f"claim_mismatch:{arg_name}!={claim_key}"],
                            metadata={
                                "argument": arg_name,
                                "claim": claim_key,
                                "expected": str(claim_val),
                                "received": str(args[arg_name]),
                            },
                        )
                        self._record(tool, args, decision, ctx)
                        return decision

        # Parameter rules validation (bounds, regex, choices)
        param_violations = self._check_parameter_rules(policy.parameter_rules, args)
        if param_violations:
            decision = Decision(
                allowed=False,
                reason=f"parameter_rule_violation:{param_violations[0]}",
                tool=tool,
                policy_source="candidate",
                violations=param_violations,
            )
            self._record(tool, args, decision, ctx)
            return decision

        # High-value action check: approval required if configured
        if policy.high_value_action == "human_approval_required":
            threshold = policy.amount_threshold if policy.amount_threshold is not None else 100.0
            # Check effective amount from args or context
            effective_amount = None
            if "amount" in args and args["amount"] is not None:
                try:
                    effective_amount = float(args["amount"])
                except (ValueError, TypeError):
                    pass
            elif ctx.amount is not None:
                effective_amount = ctx.amount

            if effective_amount is not None and effective_amount >= threshold:
                decision = Decision(
                    allowed=False,
                    reason="high_value_action:approval_required",
                    tool=tool,
                    policy_source="candidate",
                    violations=["high_value_action:approval_required"],
                    metadata={"amount": effective_amount, "threshold": threshold},
                )
                self._record(tool, args, decision, ctx)
                return decision

        # Evaluate conditions list
        for condition in policy.conditions:
            ok, reason = self._check_condition(condition, args, ctx, policy)
            if not ok:
                decision = Decision(
                    allowed=False,
                    reason=reason,
                    tool=tool,
                    policy_source="candidate",
                    violations=[reason],
                )
                self._record(tool, args, decision, ctx)
                return decision

        decision = Decision(
            allowed=True,
            reason="all_conditions_met",
            tool=tool,
            policy_source="candidate",
        )
        self._record(tool, args, decision, ctx)
        return decision

    def _check_condition(
        self,
        condition: str,
        arguments: dict[str, Any],
        context: SecurityContext,
        policy: ToolPolicy,
    ) -> tuple[bool, str]:
        """Evaluates a single condition string."""
        # Claims match expressions: e.g. "claims_match:customer_id==user_id"
        if condition.startswith(("claims_match:", "claim_match:")):
            expr = condition.split(":", 1)[1]
            if "==" in expr:
                left, right = [s.strip() for s in expr.split("==", 1)]
                if left in arguments:
                    arg_name, claim_name = left, right
                    arg_val = arguments[left]
                    claim_val = context.get_claim(right)
                elif right in arguments:
                    arg_name, claim_name = right, left
                    arg_val = arguments[right]
                    claim_val = context.get_claim(left)
                else:
                    return True, "ok"

                if claim_val is None:
                    return False, f"missing_context_claim:{claim_name}"
                if str(arg_val) != str(claim_val):
                    return False, f"claim_mismatch:{arg_name}!={claim_name}"
                return True, "ok"

        # Built-in condition checks matching RAVEN catalog & ADR requirement 8
        if condition == "verified_order_id_present":
            order_id = arguments.get("order_id") or context.order_id
            if not context.verified_order_id or not order_id:
                return False, "missing_verified_order_id"
            return True, "ok"

        if condition == "verified_user_present":
            if not context.verified_user:
                return False, "missing_verified_user"
            return True, "ok"

        if condition == "amount_below_threshold":
            threshold = policy.amount_threshold if policy.amount_threshold is not None else 100.0
            amt: float | None = None
            if "amount" in arguments and arguments["amount"] is not None:
                try:
                    amt = float(arguments["amount"])
                except (ValueError, TypeError):
                    return False, "malformed_arguments:invalid_amount_type"
            elif context.amount is not None:
                amt = context.amount

            if amt is None:
                # If amount condition is required but no amount given, fail closed
                return False, "missing_amount_for_threshold_check"
            if amt >= threshold:
                return False, "amount_at_or_above_threshold"
            return True, "ok"

        if condition == "user_id_matches_context":
            arg_uid = arguments.get("user_id") or arguments.get("customer_id")
            ctx_uid = context.get_claim("user_id") or context.user_id
            if arg_uid and ctx_uid and str(arg_uid) != str(ctx_uid):
                return False, "user_id_mismatch"
            return True, "ok"

        if condition in ("tenant_id_matches_context", "tenant_matches_context"):
            arg_tid = arguments.get("tenant_id")
            ctx_tid = context.get_claim("tenant_id")
            if arg_tid and ctx_tid and str(arg_tid) != str(ctx_tid):
                return False, "tenant_id_mismatch"
            return True, "ok"

        if condition == "account_id_matches_context":
            arg_aid = arguments.get("account_id")
            ctx_aid = context.get_claim("account_id")
            if arg_aid and ctx_aid and str(arg_aid) != str(ctx_aid):
                return False, "account_id_mismatch"
            return True, "ok"

        # Check custom condition registry
        if condition in self._custom_conditions:
            try:
                return self._custom_conditions[condition](arguments, context, policy)
            except Exception as err:  # noqa: BLE001
                return False, f"custom_condition_error:{condition}:{err}"

        return False, f"unknown_condition:{condition}"

    @staticmethod
    def _check_parameter_rules(rules: dict[str, Any], arguments: dict[str, Any]) -> list[str]:
        """Evaluates min/max/regex/in constraints on specific parameters."""
        violations: list[str] = []
        for param_name, rule_spec in rules.items():
            if param_name not in arguments:
                if rule_spec.get("required", False):
                    violations.append(f"{param_name}:required")
                continue

            val = arguments[param_name]
            if not isinstance(rule_spec, dict):
                continue

            # Numeric bounds
            if "max" in rule_spec:
                try:
                    if float(val) > float(rule_spec["max"]):
                        violations.append(f"{param_name}:exceeds_max_{rule_spec['max']}")
                except (ValueError, TypeError):
                    violations.append(f"{param_name}:not_numeric")

            if "min" in rule_spec:
                try:
                    if float(val) < float(rule_spec["min"]):
                        violations.append(f"{param_name}:below_min_{rule_spec['min']}")
                except (ValueError, TypeError):
                    violations.append(f"{param_name}:not_numeric")

            # Choice constraints
            if "in" in rule_spec and val not in rule_spec["in"]:
                violations.append(f"{param_name}:not_in_allowed_choices")

            # Regex constraints
            if "regex" in rule_spec and isinstance(val, str) and not re.search(rule_spec["regex"], val):
                violations.append(f"{param_name}:regex_mismatch")

        return violations

    def _record(
        self,
        tool: str,
        arguments: dict[str, Any],
        decision: Decision,
        context: SecurityContext | None,
    ) -> None:
        """Records an authorization decision in the in-memory audit ledger and emits telemetry."""
        ctx_obj = SecurityContext.from_any(context) if context else None
        entry = {
            "timestamp": datetime.now(UTC).isoformat(),
            "tool": tool,
            "arguments": arguments,
            "allowed": decision.allowed,
            "reason": decision.reason,
            "policy_source": decision.policy_source,
            "violations": list(decision.violations),
            "context_summary": {
                "verified_user": ctx_obj.verified_user if ctx_obj else False,
                "verified_order_id": ctx_obj.verified_order_id if ctx_obj else False,
                "user_id": ctx_obj.user_id if ctx_obj else None,
                "order_id": ctx_obj.order_id if ctx_obj else None,
            },
        }
        self.decisions.append(entry)
        if len(self.decisions) > self.audit_log_size:
            self.decisions.pop(0)

        # Emit structured security audit telemetry
        event_type = "tool_call_authorized" if decision.allowed else "tool_call_blocked"
        if decision.reason == "high_value_action:approval_required":
            event_type = "high_value_action_escalated"

        emit_security_event(
            SecurityAuditEvent(
                event_type=event_type,
                tool=tool,
                allowed=decision.allowed,
                reason=decision.reason,
                violations=list(decision.violations),
                arguments=dict(arguments),
                user_id=ctx_obj.user_id if ctx_obj else None,
                session_id=ctx_obj.session_id if ctx_obj else None,
                claims_summary=dict(ctx_obj.claims) if ctx_obj else {},
                policy_source=decision.policy_source,
                metadata=dict(decision.metadata),
            )
        )

    def protect(
        self,
        tool: str | None = None,
        on_violation: str | Callable[..., Any] = "raise",
    ) -> Callable[[Callable[..., Any]], Callable[..., Any]]:
        """Decorator that fail-closed authorizes calls to python functions / tools.

        Args:
            tool: Tool identifier in policy (defaults to func.__name__).
            on_violation: 'raise' (default), 'return_decision', or custom callback.

        Raises:
            ApprovalRequiredError: When human approval is required.
            PolicyViolationError: When unauthorized under policy.
        """

        def decorator(func: Callable[..., Any]) -> Callable[..., Any]:
            target_tool = tool or func.__name__
            sig = inspect.signature(func)

            def _prepare_call(args: tuple[Any, ...], kwargs: dict[str, Any]) -> tuple[dict[str, Any], SecurityContext]:
                bound = sig.bind_partial(*args, **kwargs)
                bound.apply_defaults()
                call_args = dict(bound.arguments)

                # Extract context if passed as parameter
                explicit_ctx = call_args.pop("_context", None)
                if explicit_ctx is None:
                    explicit_ctx = call_args.pop("context", None)

                effective_ctx = SecurityContext.from_any(explicit_ctx) if explicit_ctx is not None else (get_current_context() or SecurityContext())

                return call_args, effective_ctx

            def _handle_denial(decision: Decision, call_args: dict[str, Any]) -> Any:
                if on_violation == "return_decision":
                    return decision
                if callable(on_violation):
                    return on_violation(decision, call_args)

                # Default: raise security exception
                if decision.reason == "high_value_action:approval_required":
                    raise ApprovalRequiredError(
                        f"Action '{target_tool}' requires explicit human approval: {decision.reason}",
                        tool=target_tool,
                        reason=decision.reason,
                        decision=decision,
                        arguments=call_args,
                    )
                if "malformed_arguments" in decision.reason:
                    raise MalformedArgumentsError(
                        f"Malformed arguments for '{target_tool}': {decision.reason}",
                        tool=target_tool,
                        reason=decision.reason,
                        decision=decision,
                        arguments=call_args,
                    )
                raise PolicyViolationError(
                    f"Policy violation on '{target_tool}': {decision.reason}",
                    tool=target_tool,
                    reason=decision.reason,
                    decision=decision,
                    arguments=call_args,
                )

            if inspect.iscoroutinefunction(func):

                @functools.wraps(func)
                async def async_wrapper(*args: Any, **kwargs: Any) -> Any:
                    call_args, effective_ctx = _prepare_call(args, kwargs)
                    decision = self.authorize(target_tool, call_args, effective_ctx)
                    if not decision.allowed:
                        return _handle_denial(decision, call_args)
                    return await func(*args, **kwargs)

                return async_wrapper

            @functools.wraps(func)
            def sync_wrapper(*args: Any, **kwargs: Any) -> Any:
                call_args, effective_ctx = _prepare_call(args, kwargs)
                decision = self.authorize(target_tool, call_args, effective_ctx)
                if not decision.allowed:
                    return _handle_denial(decision, call_args)
                return func(*args, **kwargs)

            return sync_wrapper

        return decorator
