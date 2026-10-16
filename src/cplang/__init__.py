"""The CHOKR Policy Language: AI agent governance as code, a deterministic policy language and its engine.

Load a policy with `load_policy`, then decide actions with `RuleEvaluator`. The data types (`Action`, `Signal`,
`Verdict` and the types they are built from) are plain, fully typed data.
"""

from cplang.declarations import DeclarationSet, load_declarations
from cplang.errors import AuthoringError, AuthoringErrorInfo, CplError
from cplang.evaluator import RuleEvaluator
from cplang.functions import FunctionRegistry, HostFunction
from cplang.jsontypes import JsonValue
from cplang.model import (
    Action,
    Edit,
    Mode,
    Modifications,
    Obligation,
    Outcome,
    PolicyRef,
    Posture,
    Reason,
    Severity,
    Signal,
    Strategy,
    Verdict,
)
from cplang.policy import CompiledPolicy, PolicyWarning, load_policy
from cplang.profile import NEUTRAL, Failure, Profile, RuleKey, SignalEffect
from cplang.runtime import CplLimits

__version__ = "0.0.1"
LANGUAGE_VERSION = "1.0"

__all__ = [
    "LANGUAGE_VERSION",
    "NEUTRAL",
    "Action",
    "AuthoringError",
    "AuthoringErrorInfo",
    "CompiledPolicy",
    "CplError",
    "CplLimits",
    "DeclarationSet",
    "Edit",
    "Failure",
    "FunctionRegistry",
    "HostFunction",
    "JsonValue",
    "Mode",
    "Modifications",
    "Obligation",
    "Outcome",
    "PolicyRef",
    "PolicyWarning",
    "Posture",
    "Profile",
    "Reason",
    "RuleEvaluator",
    "RuleKey",
    "Severity",
    "Signal",
    "SignalEffect",
    "Strategy",
    "Verdict",
    "load_declarations",
    "load_policy",
]
