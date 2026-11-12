"""RPC ownership spans sending, waiting, cancellation, and caller failures."""
from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import pytest

from backend.application import BackendRuntime, use_runtime
from backend.agents.gateway import AgentGateway
from backend.agents.mcp import probe_stable_agent_mcp
from backend.models import AgentMcpConfig, AgentRemoteConfig, User


@pytest.mark.parametrize('failure', [RuntimeError('send failed'), asyncio.CancelledError()])
def test_mcp_probe_releases_waiter_when_send_raises(failure):
    async def scenario():
        runtime = BackendRuntime(store=object())
        observed = []

        async def store_call(*args, **kwargs):
            return {'user_id': 'owner'}

        async def send(*args, **kwargs):
            observed.extend(runtime.agents.mcp_probe_waiters.values())
            raise failure

        runtime.store_runner = store_call
        with use_runtime(runtime), patch(
            'backend.agents.configuration._stored_agent_config', return_value=AgentRemoteConfig(),
        ), patch(
            'backend.agents.configuration._mcp_target_config', return_value=AgentMcpConfig(enabled=True),
        ), patch(
            'backend.agents.directory.resolve_agent_connection_async',
            AsyncMock(return_value=('agent', object())),
        ), patch('backend.agents.gateway.send_agent_command', send):
            with pytest.raises(type(failure)):
                await probe_stable_agent_mcp(
                    'stable', 'code_graph', User(user_id='owner', username='owner', role='user'),
                )
        assert len(observed) == 1
        assert observed[0].cancelled()
        assert not runtime.agents.mcp_probe_waiters

    asyncio.run(scenario())


@pytest.mark.parametrize('outcome', ['offline', 'timeout', 'cancelled', 'reply'])
def test_gateway_releases_each_request_and_keeps_local_reply_fast(outcome):
    async def scenario():
        runtime = BackendRuntime(store=object())
        observed = []

        async def send(agent_id, command):
            waiter = runtime.agents.code_graph_waiters[command['request_id']]
            observed.append(waiter)
            if outcome == 'cancelled':
                raise asyncio.CancelledError()
            if outcome == 'reply':
                waiter.set_result({'ok': True, 'request_id': command['request_id']})
            return outcome != 'offline'

        # A completed local reply must not query the distributed mailbox/store.
        runtime.store_runner = AsyncMock(side_effect=AssertionError('unexpected storage call'))
        with patch('backend.agents.gateway.send_agent_command', send):
            operation = AgentGateway(runtime).request(
                'agent', {'type': 'code_graph_update'}, response_type='code_graph_result', timeout=0,
            )
            if outcome == 'cancelled':
                with pytest.raises(asyncio.CancelledError):
                    await operation
            elif outcome == 'timeout':
                with pytest.raises(asyncio.TimeoutError):
                    await operation
            else:
                result = await operation
                assert (result is None) == (outcome == 'offline')
        assert len(observed) == 1
        assert observed[0].done()
        assert not runtime.agents.code_graph_waiters
        runtime.store_runner.assert_not_called()

    asyncio.run(scenario())
