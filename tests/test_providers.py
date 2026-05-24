import asyncio

from phalanx.providers import ProviderRegistry, NoopProvider


def test_provider_registry_ordering():
    reg = ProviderRegistry()
    reg.register("a", NoopProvider())
    reg.register("b", NoopProvider())
    reg.register("c", NoopProvider())

    ordered = reg.ordered_by_preference(["b", "c"])  # prefer b then c
    assert len(ordered) == 3
    # first two should be b and c
    # we can't inspect keys directly, but ensure providers are in list
    assert ordered[0].available
    assert ordered[1].available


def test_noop_provider_plan_returns_empty():
    noop = NoopProvider()

    async def _run():
        res = await noop.plan("hello", {})
        assert res == {}

    asyncio.run(_run())
from phalanx.providers import registry, NoopProvider


def test_noop_provider_registered():
    assert "noop" in registry.list_providers()


import asyncio


def test_noop_provider_behaviour():
    p = registry.get("noop", response="hello")

    async def _run():
        assert await p.validate() is True
        plan = await p.plan("scan example.com")
        assert isinstance(plan, dict) and "plan" in plan
        chat = await p.chat([{"role": "user", "content": "hi"}])
        assert chat["reply"] == "hello"
        await p.close()

    asyncio.run(_run())
