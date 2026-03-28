"""Unit tests for InMemoryClientHost."""

import pytest
from cdk_spilman_kit.in_memory_client_host import InMemoryClientHost


class TestInMemoryClientHost:
    """Tests for InMemoryClientHost storage methods."""

    @pytest.fixture
    def host(self):
        # Use a dummy secret key (32 bytes hex = 64 chars)
        secret_key = "0" * 64
        return InMemoryClientHost(secret_key)

    # ========================================================================
    # Channel Funding
    # ========================================================================

    def test_save_and_get_channel_funding(self, host):
        """Test saving and retrieving channel funding."""
        channel_id = "channel-123"
        funding_json = '{"capacity": 1000}'

        host.save_opening_channel(channel_id, funding_json)
        result = host.get_channel_funding(channel_id)

        assert result == funding_json

    def test_get_channel_funding_not_found(self, host):
        """Test getting non-existent channel returns None."""
        result = host.get_channel_funding("nonexistent")
        assert result is None

    def test_save_opening_channel_sets_state_opening(self, host):
        """Test that saving opening channel sets state to opening."""
        channel_id = "channel-123"
        host.save_opening_channel(channel_id, '{"capacity": 1000}')

        assert host.get_channel_state(channel_id) == "opening"

    def test_mark_channel_open_sets_state_open(self, host):
        """Test that mark_channel_open transitions state to open."""
        channel_id = "channel-123"
        host.save_opening_channel(channel_id, '{"capacity": 1000}')
        host.mark_channel_open(channel_id, "[]")

        assert host.get_channel_state(channel_id) == "open"

    # ========================================================================
    # Payment State
    # ========================================================================

    def test_record_and_get_payment_state(self, host):
        """Test recording and retrieving payment state."""
        channel_id = "channel-123"
        state_json = '{"balance": 500}'

        host.record_payment(channel_id, state_json)
        result = host.get_payment_state(channel_id)

        assert result == state_json

    def test_get_payment_state_not_found(self, host):
        """Test getting non-existent payment state returns None."""
        result = host.get_payment_state("nonexistent")
        assert result is None

    def test_record_payment_overwrites(self, host):
        """Test that recording payment overwrites previous state."""
        channel_id = "channel-123"
        host.record_payment(channel_id, '{"balance": 500}')
        host.record_payment(channel_id, '{"balance": 300}')

        result = host.get_payment_state(channel_id)
        assert result == '{"balance": 300}'

    # ========================================================================
    # Channel Lifecycle
    # ========================================================================

    def test_get_channel_state_default_open(self, host):
        """Test that unknown channel state defaults to 'open'."""
        result = host.get_channel_state("unknown-channel")
        assert result == "open"

    def test_mark_channel_closed(self, host):
        """Test marking a channel as closed."""
        channel_id = "channel-123"
        host.save_opening_channel(channel_id, '{"capacity": 1000}')
        host.mark_channel_open(channel_id, "[]")

        host.mark_channel_closed(channel_id)

        assert host.get_channel_state(channel_id) == "closed"

    def test_list_channel_ids_empty(self, host):
        """Test listing channels when none exist."""
        result = host.list_channel_ids()
        assert result == []

    def test_list_channel_ids(self, host):
        """Test listing channel IDs."""
        host.save_opening_channel("channel-1", '{"capacity": 100}')
        host.save_opening_channel("channel-2", '{"capacity": 200}')

        result = host.list_channel_ids()

        assert set(result) == {"channel-1", "channel-2"}

    def test_delete_channel(self, host):
        """Test deleting a channel removes all data."""
        channel_id = "channel-123"
        host.save_opening_channel(channel_id, '{"capacity": 1000}')
        host.record_payment(channel_id, '{"balance": 500}')
        host.mark_channel_closed(channel_id)

        host.delete_channel(channel_id)

        assert host.get_channel_funding(channel_id) is None
        assert host.get_payment_state(channel_id) is None
        assert channel_id not in host.list_channel_ids()
        # After deletion, state should default back to "open"
        assert host.get_channel_state(channel_id) == "open"

    def test_delete_nonexistent_channel(self, host):
        """Test deleting a non-existent channel doesn't raise."""
        # Should not raise
        host.delete_channel("nonexistent")

    # ========================================================================
    # Time
    # ========================================================================

    def test_now_seconds(self, host):
        """Test that now_seconds returns a reasonable timestamp."""
        import time

        before = int(time.time())
        result = host.now_seconds()
        after = int(time.time())

        assert before <= result <= after
