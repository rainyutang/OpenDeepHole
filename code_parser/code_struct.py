"""Data classes for parsed C/C++ code structures."""

from dataclasses import dataclass, field


@dataclass
class FunctionLite:
    name: str
    signature: str
    return_type: str
    file: str
    start_line: int
    end_line: int
    is_static: bool
    linkage: str
    body: str
    calls: list["FunctionCall"] = field(default_factory=list)


@dataclass
class StructLite:
    name: str
    file: str
    start_line: int
    end_line: int
    definition: str


@dataclass
class FunctionCall:
    caller_function: str
    callee_name: str
    file: str
    line: int
    column: int


@dataclass
class GlobalVariable:
    name: str
    file: str
    start_line: int
    end_line: int
    is_extern: bool
    is_static: bool
    definition: str


@dataclass
class VariableReference:
    variable_name: str
    file: str
    function: str
    line: int
    column: int
    context: str
    access_type: str
