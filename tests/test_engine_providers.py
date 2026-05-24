from phalanx.engine import ExecutionEngine


def test_engine_registers_providers():
    # Create engine with minimal config to trigger provider setup
    engine = ExecutionEngine(config={"model_provider": "auto"})
    # Planner should have at least one provider registered (noop fallback)
    providers = getattr(engine, "_planner")._providers
    assert providers and len(providers) >= 1
