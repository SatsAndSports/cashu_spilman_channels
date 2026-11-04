"""Complete HTTP evidence for Rust callbacks; exceptions mean transport failure."""

import json


def mint_response_envelope(response) -> str:
    """Return both success and error statuses without repairing invalid UTF-8."""
    return json.dumps({"status": response.status_code, "body": response.content.decode("utf-8")})
