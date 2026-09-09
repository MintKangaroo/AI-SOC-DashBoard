"""Concurrent aggregate requests share work without retaining stale evidence."""
from concurrent.futures import ThreadPoolExecutor
import threading

import pytest

from modules import console_store
from scripts.loadtest import percentile, run_round, summarize


@pytest.mark.parametrize('fails', [False, True])
def test_identical_reads_share_inflight_result_and_recover(monkeypatch, fails):
    entered, release, waiting = threading.Event(), threading.Event(), threading.Event()
    counter_lock, counter = threading.Lock(), [0]
    original = console_store.Future
    class TrackedFuture(original):
        def result(self, *args, **kwargs):
            with counter_lock:
                counter[0] += 1
                if counter[0] == 3:
                    waiting.set()
            return super().result(*args, **kwargs)
    monkeypatch.setattr(console_store, 'Future', TrackedFuture)
    reads = console_store.CoalescedReads()
    def produce():
        entered.set()
        assert release.wait(5)
        if fails:
            raise ValueError('Measured read failure')
        return {'evidence':'initial snapshot'}
    with ThreadPoolExecutor(max_workers=4) as pool:
        tasks = [pool.submit(reads.run, ('quality',24), produce)]
        assert entered.wait(5)
        tasks.extend(pool.submit(reads.run, ('quality',24), produce) for _ in range(3))
        try:
            assert waiting.wait(5)
            # Different filters must not receive the first query's evidence.
            assert reads.run(('quality',1), lambda: 'another scope') == 'another scope'
        finally:
            release.set()
        for task in tasks:
            if fails:
                with pytest.raises(ValueError, match='Measured read failure'):
                    task.result(5)
            else:
                assert task.result(5) == {'evidence':'initial snapshot'}
    assert reads.run(('quality',24), lambda: 'updated verdict') == 'updated verdict'
    assert reads._pending == {}


def test_distinct_read_keys_cannot_grow_registry_without_bound():
    reads = console_store.CoalescedReads()
    entered, release = threading.Barrier(17), threading.Event()
    def produce():
        entered.wait(timeout=5)
        assert release.wait(5)
        return 'retained until read finishes'
    with ThreadPoolExecutor(max_workers=16) as pool:
        tasks = [pool.submit(reads.run, key, produce) for key in range(16)]
        try:
            entered.wait(timeout=5)
            assert len(reads._pending) == 16
            assert reads.run(17, lambda: 'bounded overflow read') == 'bounded overflow read'
            assert len(reads._pending) == 16
        finally:
            release.set()
        assert all(task.result(5) for task in tasks)
    assert not reads._pending


def test_load_percentiles_and_http_errors_are_not_hidden():
    assert percentile([], .95) is None
    assert summarize([10,20,30,1000]) == {'samples':4,'p50_ms':20,'p95_ms':1000,'max_ms':1000}
    class FailingOpener:
        def open(self, *args, **kwargs):
            raise OSError('Isolated failure')
    stats, elapsed, failures, requests = run_round('http://unused', [('/read',8)], 4, FailingOpener())
    assert failures == requests == 8 and len(stats['/read']) == 8
    assert elapsed > 0
