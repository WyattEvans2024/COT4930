import hashlib
import json
from typing import Literal

from fastmcp import FastMCP


mcp = FastMCP("text-tools")


@mcp.tool()
def word_count(text: str) -> dict[str, int]:
    """Count the words, characters, and lines in a text string.

    Words are separated by whitespace, characters are counted using Python's
    string length, and lines are counted using ``str.splitlines()``. An empty
    string therefore has zero words and zero lines.

    Args:
        text: The text to measure.

    Returns:
        A dictionary with integer ``words``, ``characters``, and ``lines``
        counts.
    """
    return {
        "words": len(text.split()),
        "characters": len(text),
        "lines": len(text.splitlines()),
    }


@mcp.tool()
def hash_text(text: str) -> str:
    """Calculate the SHA-256 hexadecimal digest of a text string.

    The string is encoded as UTF-8 before hashing.

    Args:
        text: The text whose SHA-256 digest should be calculated.

    Returns:
        The lowercase, 64-character hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


@mcp.tool()
def convert_case(text: str, case_style: Literal["upper", "lower", "title"]) -> str:
    """Convert text to the requested letter case.

    Args:
        text: The text to convert.
        case_style: The target case; one of ``"upper"``, ``"lower"``, or
            ``"title"``.

    Returns:
        The converted text.
    """
    converters = {
        "upper": str.upper,
        "lower": str.lower,
        "title": str.title,
    }
    try:
        converter = converters[case_style]
    except KeyError:
        raise ValueError(
            "case_style must be one of: upper, lower, title"
        ) from None
    return converter(text)


@mcp.tool()
def validate_json(text: str) -> dict[str, object]:
    """Check whether a string contains valid JSON and return its result.

    Args:
        text: The string to parse as JSON.

    Returns:
        A dictionary with ``valid`` set to ``True`` and ``parsed`` set to the
        decoded JSON structure when parsing succeeds. Otherwise, returns a
        dictionary with ``valid`` set to ``False`` and ``error`` set to the
        JSON parser's error message.
    """
    try:
        return {"valid": True, "parsed": json.loads(text)}
    except json.JSONDecodeError as error:
        return {"valid": False, "error": str(error)}


if __name__ == "__main__":
    mcp.run(transport="stdio", log_level="WARNING")
