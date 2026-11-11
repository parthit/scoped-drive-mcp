"""The mailbox prompt tells Grok to set up watching without a pasted webhook."""

from scoped_drive_mcp.server import INSTRUCTIONS, WATCH_MAIL


def test_watch_prompt_does_not_ask_for_a_pasted_url() -> None:
    assert "check_messages" in WATCH_MAIL
    assert "Do not ask the human to paste a webhook URL" in WATCH_MAIL
    assert "watch_mailbox" in INSTRUCTIONS
    assert "Do not ask the human to paste a webhook URL" in INSTRUCTIONS
