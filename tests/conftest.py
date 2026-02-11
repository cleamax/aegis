import pytest
from aegis.core.run import RunContext, TraceWriter
from aegis.defenses.approval_monitor import Policy

@pytest.fixture
def mock_run_context(tmp_path):
    """Creates a RunContext with a temporary directory."""
    run_dir = tmp_path / "run_test"
    run_dir.mkdir()
    trace = TraceWriter(run_dir=run_dir)
    return RunContext(run_id="test_run", run_dir=run_dir, trace=trace)

@pytest.fixture
def strict_policy():
    return Policy.default()

@pytest.fixture
def permissive_policy():
    return Policy.permissive()
