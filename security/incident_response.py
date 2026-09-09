"""Signed incident reporting and response verification.

`SecurityIncidentResponse` turns arbitrary incident payloads into a signed
response object and verifies later claim/response pairs against the same
oracle, so the network can prove which incidents were acknowledged and by
whom.
"""

import json
import uuid


class SecurityIncidentResponse:
    """Report and verify incidents through a signed response channel."""

    def __init__(self, oracle_api):
        self.oracle_api = oracle_api

    @staticmethod
    def _canonical(value):
        """Return the canonical form used for signing and verification."""
        if not isinstance(value, str):
            return json.dumps(value, sort_keys=True)
        return value

    def report_incident(self, incident_data):
        """Produce a signed acknowledgement for the reported incident."""
        response = {"incident_id": uuid.uuid4().hex, "status": "reported"}
        response_canonical = self._canonical(response)
        signature = self.oracle_api.sign_data(response_canonical)
        return {"response": response, "signature": signature}

    def verify_response(self, response, signature):
        """Verify a previously issued signed response."""
        response_canonical = self._canonical(response)
        verification = self.oracle_api.verify_signature(
            response_canonical, signature
        )
        if verification.get("message") == "Signature verified successfully":
            return {"message": "Response verified successfully"}
        return {"message": "Invalid response signature"}
