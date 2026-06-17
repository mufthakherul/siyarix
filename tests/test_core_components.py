
from siyarix.core.learning import ContinuousLearning
from siyarix.core.learning import ContinuousLearning, Experience
from siyarix.core.pipeline import CommandPipeline, PipelineStep, PipelineResult
from siyarix.core.swarm import SwarmRouter, SwarmTask, ReconAgent, ExploitAgent, ReportAgent
from unittest.mock import MagicMock, AsyncMock, patch
import asyncio
import json
import pytest



def test_pipeline_parse():
    pipeline = CommandPipeline()
    
    steps = pipeline.parse("scan 127.0.0.1")
    assert len(steps) == 1
    assert steps[0].instruction == "scan 127.0.0.1"
    
    steps = pipeline.parse("scan | grep open | report")
    assert len(steps) == 3
    assert steps[1].instruction == "grep open"
    
    steps = pipeline.parse("scan then report")
    assert len(steps) == 2
    
    steps = pipeline.parse("scan and then exploit")
    assert len(steps) == 2
    
    steps = pipeline.parse("scan followed by report")
    assert len(steps) == 2

@pytest.mark.asyncio
async def test_pipeline_execute():
    pipeline = CommandPipeline()
    steps = [PipelineStep(instruction="test 1", step_id="1"), PipelineStep(instruction="test 2", step_id="2")]
    
    async def mock_executor(step, ctx):
        if step.instruction == "test 1":
            return {"status": "completed", "findings": ["A"], "output": "Done 1"}
        elif step.instruction == "test 2":
            return {"status": "failed"}
    
    result = await pipeline.execute(steps, mock_executor)
    assert result.steps_completed == 1
    assert result.steps_failed == 1
    assert result.success is False
    assert result.all_findings == ["A"]

@pytest.mark.asyncio
async def test_pipeline_execute_exception():
    pipeline = CommandPipeline()
    steps = [PipelineStep(instruction="fail", step_id="1")]
    
    async def mock_executor(step, ctx):
        raise ValueError("Boom")
        
    result = await pipeline.execute(steps, mock_executor)
    assert result.steps_failed == 1
    assert result.success is False

@pytest.mark.asyncio
async def test_swarm_router():
    router = SwarmRouter()
    
    with patch("asyncio.sleep", new_callable=AsyncMock):
        res = await router.run_campaign("127.0.0.1")
        assert res["recon_result"] is not None
        assert res["exploit_result"] is not None
        assert res["report_result"] is not None
        assert "Mock findings by ReconAgent" in res["recon_result"]["findings"]

@pytest.mark.asyncio
async def test_continuous_learning_get_embedding():
    mock_memory = MagicMock()
    cl = ContinuousLearning(memory=mock_memory)
    
    emb1 = await cl._get_embedding("test_text")
    assert len(emb1) in (32, 1536)
    
    emb2 = await cl._get_embedding("test_text")
    assert emb1 == emb2

@pytest.mark.asyncio
async def test_continuous_learning_record_experience():
    mock_memory = MagicMock()
    cl = ContinuousLearning(memory=mock_memory)
    
    exp = Experience(target="10.0.0.1", action="scan", result="success", success=True)
    await cl.record_experience(exp)
    
    assert mock_memory.store.call_count == 1
    args, kwargs = mock_memory.store.call_args
    stored_data = json.loads(kwargs["value"])
    assert stored_data["target"] == "10.0.0.1"

def test_cosine_similarity():
    mock_memory = MagicMock()
    cl = ContinuousLearning(memory=mock_memory)
    
    v1 = [1.0, 0.0]
    v2 = [1.0, 0.0]
    v3 = [0.0, 1.0]
    
    assert cl._cosine_similarity(v1, v2) == 1.0
    assert cl._cosine_similarity(v1, v3) == 0.0
    assert cl._cosine_similarity([], []) == 0.0
    assert cl._cosine_similarity([0.0], [0.0]) == 0.0

@pytest.mark.asyncio
async def test_continuous_learning_query():
    mock_memory = MagicMock()
    
    cl = ContinuousLearning(memory=mock_memory)
    emb = await cl._get_embedding("Target: 10.0.0.1 | Action: scan")
        
    mock_entry = MagicMock()
    mock_entry.value = json.dumps({
        "target": "10.0.0.1",
        "action": "scan",
        "result": "success",
        "success": True,
        "embedding": emb
    })
    
    mock_memory.search.return_value = [mock_entry]
    
    results = await cl.query_similar_experiences("scan", "10.0.0.1")
    
    assert len(results) == 1
    assert results[0].action == "scan"

import asyncio
class TestLearningCore:
    """Cover missing learning.py lines."""

    @pytest.mark.asyncio
    async def test_get_embedding_from_openai(self):
        from siyarix.core.learning import ContinuousLearning
        mem = MagicMock()
        cl = ContinuousLearning(memory=mem)
        with patch.object(cl.providers, "get_api_key", return_value="sk-test"):
            with patch("openai.AsyncOpenAI") as MockAO:
                mock_client = AsyncMock()
                mock_client.embeddings.create = AsyncMock(
                    return_value=MagicMock(data=[MagicMock(embedding=[0.1, 0.2, 0.3])])
                )
                MockAO.return_value = mock_client
                emb = await cl._get_embedding("test text")
                assert emb == [0.1, 0.2, 0.3]

    @pytest.mark.asyncio
    async def test_get_embedding_from_ollama(self):
        from siyarix.core.learning import ContinuousLearning
        mem = MagicMock()
        cl = ContinuousLearning(memory=mem)
        cl._embedding_cache = {}
        with patch.object(cl.providers, "get_api_key", return_value=None):
            with patch.object(cl.providers, "get_base_url", return_value="http://localhost:11434"):
                with patch("httpx.AsyncClient") as MockClient:
                    mock_resp = MagicMock()
                    mock_resp.status_code = 200
                    mock_resp.json.return_value = {"embedding": [0.5, 0.6]}
                    mock_client = AsyncMock()
                    mock_client.__aenter__.return_value = mock_client
                    mock_client.post = AsyncMock(return_value=mock_resp)
                    MockClient.return_value = mock_client
                    emb = await cl._get_embedding("test")
                    assert emb == [0.5, 0.6]

    @pytest.mark.asyncio
    async def test_get_embedding_simulated_fallback(self):
        from siyarix.core.learning import ContinuousLearning
        mem = MagicMock()
        cl = ContinuousLearning(memory=mem)
        cl._embedding_cache = {}
        with patch.object(cl.providers, "get_api_key", return_value=None):
            with patch.object(cl.providers, "get_base_url", return_value=None):
                emb = await cl._get_embedding("test text")
                assert len(emb) == 32

    @pytest.mark.asyncio
    async def test_get_embedding_simulated_exception(self):
        from siyarix.core.learning import ContinuousLearning
        mem = MagicMock()
        cl = ContinuousLearning(memory=mem)
        cl._embedding_cache = {}
        with patch.object(cl.providers, "get_api_key", return_value=None):
            with patch.object(cl.providers, "get_base_url", return_value=None):
                with patch("hashlib.sha256", side_effect=Exception("fail")):
                    emb = await cl._get_embedding("test")
                    assert emb == [0.0] * 32

    @pytest.mark.asyncio
    async def test_query_similar_experiences_handles_bad_data(self):
        from siyarix.core.learning import ContinuousLearning, Experience
        mem = MagicMock()
        cl = ContinuousLearning(memory=mem)
        cl._embedding_cache["test"] = [0.1] * 32
        bad_entry = MagicMock()
        bad_entry.value = "not json"
        mem.search.return_value = [bad_entry]
        results = await cl.query_similar_experiences("scan", "target")
        assert results == []


# ═══════════════════════════════════════════════════════════════════
# credential_store.py (71% - selective key lines)
# ═══════════════════════════════════════════════════════════════════
