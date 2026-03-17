import pytest

from src.connection_limiter import ConnectionLimiter


@pytest.mark.asyncio
async def test_try_acquire_allows_until_total_limit():
    limiter = ConnectionLimiter(max_connections=3, max_connections_per_ip=3)

    ok1, reason1 = await limiter.try_acquire("1.1.1.1")
    ok2, reason2 = await limiter.try_acquire("2.2.2.2")
    ok3, reason3 = await limiter.try_acquire("3.3.3.3")

    assert ok1 is True and reason1 is None
    assert ok2 is True and reason2 is None
    assert ok3 is True and reason3 is None

    active_total, active_by_ip = await limiter.current_active()
    assert active_total == 3
    assert active_by_ip == {
        "1.1.1.1": 1,
        "2.2.2.2": 1,
        "3.3.3.3": 1,
    }


@pytest.mark.asyncio
async def test_try_acquire_rejects_when_total_limit_reached():
    limiter = ConnectionLimiter(max_connections=2, max_connections_per_ip=2)

    assert await limiter.try_acquire("1.1.1.1") == (True, None)
    assert await limiter.try_acquire("2.2.2.2") == (True, None)

    ok, reason = await limiter.try_acquire("3.3.3.3")

    assert ok is False
    assert reason == "server_full"

    active_total, active_by_ip = await limiter.current_active()
    assert active_total == 2
    assert active_by_ip == {
        "1.1.1.1": 1,
        "2.2.2.2": 1,
    }


@pytest.mark.asyncio
async def test_try_acquire_rejects_when_per_ip_limit_reached():
    limiter = ConnectionLimiter(max_connections=10, max_connections_per_ip=2)

    assert await limiter.try_acquire("1.1.1.1") == (True, None)
    assert await limiter.try_acquire("1.1.1.1") == (True, None)

    ok, reason = await limiter.try_acquire("1.1.1.1")

    assert ok is False
    assert reason == "per_ip_limit"

    active_total, active_by_ip = await limiter.current_active()
    assert active_total == 2
    assert active_by_ip == {"1.1.1.1": 2}


@pytest.mark.asyncio
async def test_release_frees_capacity_for_same_ip():
    limiter = ConnectionLimiter(max_connections=3, max_connections_per_ip=2)

    assert await limiter.try_acquire("1.1.1.1") == (True, None)
    assert await limiter.try_acquire("1.1.1.1") == (True, None)

    ok, reason = await limiter.try_acquire("1.1.1.1")
    assert ok is False
    assert reason == "per_ip_limit"

    await limiter.release("1.1.1.1")

    ok, reason = await limiter.try_acquire("1.1.1.1")
    assert ok is True
    assert reason is None

    active_total, active_by_ip = await limiter.current_active()
    assert active_total == 2
    assert active_by_ip == {"1.1.1.1": 2}


@pytest.mark.asyncio
async def test_release_frees_capacity_for_other_ip_after_total_limit():
    limiter = ConnectionLimiter(max_connections=2, max_connections_per_ip=2)

    assert await limiter.try_acquire("1.1.1.1") == (True, None)
    assert await limiter.try_acquire("2.2.2.2") == (True, None)

    ok, reason = await limiter.try_acquire("3.3.3.3")
    assert ok is False
    assert reason == "server_full"

    await limiter.release("1.1.1.1")

    ok, reason = await limiter.try_acquire("3.3.3.3")
    assert ok is True
    assert reason is None

    active_total, active_by_ip = await limiter.current_active()
    assert active_total == 2
    assert active_by_ip == {
        "2.2.2.2": 1,
        "3.3.3.3": 1,
    }


@pytest.mark.asyncio
async def test_release_unknown_ip_is_noop():
    limiter = ConnectionLimiter(max_connections=2, max_connections_per_ip=2)

    assert await limiter.try_acquire("1.1.1.1") == (True, None)

    await limiter.release("9.9.9.9")

    active_total, active_by_ip = await limiter.current_active()
    assert active_total == 1
    assert active_by_ip == {"1.1.1.1": 1}


@pytest.mark.asyncio
async def test_release_removes_ip_entry_when_count_reaches_zero():
    limiter = ConnectionLimiter(max_connections=3, max_connections_per_ip=3)

    assert await limiter.try_acquire("1.1.1.1") == (True, None)

    await limiter.release("1.1.1.1")

    active_total, active_by_ip = await limiter.current_active()
    assert active_total == 0
    assert active_by_ip == {}


def test_init_rejects_non_positive_limits():
    with pytest.raises(ValueError):
        ConnectionLimiter(max_connections=0, max_connections_per_ip=1)

    with pytest.raises(ValueError):
        ConnectionLimiter(max_connections=1, max_connections_per_ip=0)


def test_init_rejects_per_ip_above_total_limit():
    with pytest.raises(ValueError):
        ConnectionLimiter(max_connections=2, max_connections_per_ip=3)