import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from agent import fp_reviewer


class AgentFeedbackTests(unittest.TestCase):
    def test_update_local_feedback_replaces_existing_entry(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            feedback_file = Path(tmp) / "fp_feedback.json"
            with patch.object(fp_reviewer, "_FP_FEEDBACK_FILE", feedback_file):
                fp_reviewer.update_local_feedback(
                    {"id": "fb-1", "vuln_type": "npd", "reason": "old"}
                )
                fp_reviewer.update_local_feedback(
                    {"id": "fb-1", "vuln_type": "npd", "reason": "new"}
                )

                feedback = fp_reviewer.load_local_feedback()
                self.assertEqual(feedback["npd"], [
                    {"id": "fb-1", "vuln_type": "npd", "reason": "new"}
                ])


if __name__ == "__main__":
    unittest.main()
