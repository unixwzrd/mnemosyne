#!/usr/bin/env python3
"""Tests for Weibull Decay, MMR Re-ranking, and Query Intent modules."""

import sys
import os
import unittest
import tempfile
import time
import json
from datetime import datetime
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
os.environ.setdefault("MNEMOSYNE_DATA_DIR", tempfile.mkdtemp())


class TestWeibullDecay(unittest.TestCase):
    def test_weibull_params_exist(self):
        from mnemosyne.core.weibull import WEIBULL_PARAMS
        expected_types = ["profile", "preference", "setup", "fact", "learning",
                         "pattern", "project", "goal", "entity", "event", "issue",
                         "request", "general"]
        for t in expected_types:
            self.assertIn(t, WEIBULL_PARAMS)
            self.assertIn("k", WEIBULL_PARAMS[t])
            self.assertIn("eta", WEIBULL_PARAMS[t])

    def test_profile_decay_is_slow(self):
        from mnemosyne.core.weibull import weibull_decay_factor
        age = 720
        profile_decay = weibull_decay_factor(age, "profile")
        request_decay = weibull_decay_factor(age, "request")
        self.assertGreater(profile_decay, request_decay)
        self.assertGreater(profile_decay, 0.5)

    def test_request_decay_is_fast(self):
        from mnemosyne.core.weibull import weibull_decay_factor
        age = 168
        request_decay = weibull_decay_factor(age, "request")
        self.assertLess(request_decay, 0.1)

    def test_fresh_memory_boost_is_one(self):
        from mnemosyne.core.weibull import weibull_boost
        now = datetime.now()
        boost = weibull_boost(now.isoformat(), now, memory_type="general")
        self.assertAlmostEqual(boost, 1.0, places=5)

    def test_weibull_vs_exponential(self):
        from mnemosyne.core.weibull import weibull_decay_factor
        import math
        age = 5000
        weibull_val = weibull_decay_factor(age, "profile")
        exp_val = math.exp(-age / 168)
        self.assertGreater(weibull_val, exp_val)

    def test_general_type_uses_exponential(self):
        from mnemosyne.core.weibull import weibull_decay_factor
        import math
        age = 168
        weibull_val = weibull_decay_factor(age, "general")
        exp_val = math.exp(-age / 168.0)
        self.assertAlmostEqual(weibull_val, exp_val, places=5)

    def test_invalid_timestamp_returns_zero(self):
        from mnemosyne.core.weibull import weibull_boost
        boost = weibull_boost("not-a-date", memory_type="general")
        self.assertEqual(boost, 0.0)

    def test_none_timestamp_returns_zero(self):
        from mnemosyne.core.weibull import weibull_boost
        boost = weibull_boost(None, memory_type="general")
        self.assertEqual(boost, 0.0)


class TestQueryIntent(unittest.TestCase):
    def test_temporal_intent(self):
        from mnemosyne.core.query_intent import classify_intent
        intent = classify_intent("what happened last Monday")
        self.assertEqual(intent.category, "temporal")
        self.assertGreater(intent.confidence, 0.3)

    def test_factual_intent(self):
        from mnemosyne.core.query_intent import classify_intent
        intent = classify_intent("what is the database password")
        self.assertEqual(intent.category, "factual")

    def test_preference_intent(self):
        from mnemosyne.core.query_intent import classify_intent
        intent = classify_intent("what does Denis prefer for lunch")
        self.assertIn(intent.category, ["preference", "entity"])

    def test_procedural_intent(self):
        from mnemosyne.core.query_intent import classify_intent
        intent = classify_intent("how do I deploy this project")
        self.assertEqual(intent.category, "procedural")

    def test_general_intent(self):
        from mnemosyne.core.query_intent import classify_intent
        intent = classify_intent("hello world test")
        self.assertEqual(intent.category, "general")
        self.assertEqual(intent.confidence, 0.0)

    def test_weight_adjustment(self):
        from mnemosyne.core.query_intent import classify_intent, adjust_weights
        intent = classify_intent("what happened last week")
        vw, fw, iw = adjust_weights(0.5, 0.3, 0.2, intent=intent)
        self.assertGreater(fw, vw, "Temporal intent should boost FTS over vector")
        self.assertAlmostEqual(vw + fw + iw, 1.0, places=5)


class TestMMRRerank(unittest.TestCase):
    def test_mmr_rerank_no_duplicates(self):
        from mnemosyne.core.mmr import mmr_rerank
        results = [
            {"content": "database password is hunter2", "score": 0.95},
            {"content": "server runs on port 8080", "score": 0.85},
            {"content": "deploy script is in /opt/deploy", "score": 0.80},
        ]
        reranked = mmr_rerank(results, lambda_param=0.7, top_k=3)
        self.assertEqual(len(reranked), 3)
        self.assertEqual(reranked[0]["content"], "database password is hunter2")

    def test_mmr_diversifies_similar_results(self):
        from mnemosyne.core.mmr import mmr_rerank
        results = [
            {"content": "the database password is hunter2", "score": 0.95},
            {"content": "the database password was hunter2", "score": 0.94},
            {"content": "the database password should be hunter2", "score": 0.93},
            {"content": "unrelated topic about gardening", "score": 0.50},
        ]
        reranked = mmr_rerank(results, lambda_param=0.5, top_k=3)
        contents = [r["content"] for r in reranked]
        self.assertIn("unrelated topic about gardening", contents)

    def test_mmr_single_result(self):
        from mnemosyne.core.mmr import mmr_rerank
        results = [{"content": "only one result", "score": 0.5}]
        reranked = mmr_rerank(results)
        self.assertEqual(len(reranked), 1)

    def test_empty_results(self):
        from mnemosyne.core.mmr import mmr_rerank
        reranked = mmr_rerank([])
        self.assertEqual(len(reranked), 0)


class TestEnhancedRecallE2E(unittest.TestCase):
    """End-to-end test of recall_enhanced() with weibull + mmr + intent."""

    def setUp(self):
        os.environ["MNEMOSYNE_ENHANCED_RECALL"] = "1"
        self.tmpdir = tempfile.mkdtemp()
        self.db_path = Path(self.tmpdir) / "test_enhanced.db"
        from mnemosyne.core.beam import BeamMemory, init_beam
        init_beam(self.db_path)
        self.beam = BeamMemory(session_id="test_enhanced", db_path=self.db_path)

    def tearDown(self):
        self.beam.conn.close()
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)
        os.environ.pop("MNEMOSYNE_ENHANCED_RECALL", None)

    def test_enhanced_recall_basic(self):
        self.beam.remember("The database password is mySecret123", source="dummy", importance=0.8)
        self.beam.remember("The server runs on port 8080 in production", source="dummy", importance=0.7)
        results = self.beam.recall_enhanced("database password", top_k=3)
        self.assertGreaterEqual(len(results), 1)
        self.assertIn("password", results[0]["content"].lower())

    def test_enhanced_recall_weibull_scoring(self):
        self.beam.remember("I prefer dark mode for all apps", source="dummy", importance=0.8)
        results = self.beam.recall_enhanced("dark mode preference", top_k=3)
        self.assertGreaterEqual(len(results), 1)
        if results:
            self.assertIn("weibull_boost", results[0])

    def test_enhanced_recall_mmr_diversity(self):
        for i in range(3):
            self.beam.remember(f"The database password is secret{i}", source="dummy", importance=0.9 - i * 0.05)
        self.beam.remember("Gardening tips: water plants daily", source="dummy", importance=0.3)
        results = self.beam.recall_enhanced("database password", top_k=4, mmr_lambda=0.5)
        self.assertGreaterEqual(len(results), 1)

    def test_enhanced_recall_backward_compat(self):
        os.environ.pop("MNEMOSYNE_ENHANCED_RECALL", None)
        self.beam.remember("Test memory for backward compat", source="dummy", importance=0.5)
        results = self.beam.recall_enhanced("test memory", top_k=3)
        self.assertGreaterEqual(len(results), 1)
        os.environ["MNEMOSYNE_ENHANCED_RECALL"] = "1"


if __name__ == "__main__":
    unittest.main()
