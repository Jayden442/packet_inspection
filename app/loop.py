import asyncio
from .state import interval_stats
from storage.retention import cleanup_old_records


async def snapshot_loop():
    
    while True:
        await asyncio.sleep(60)
        print("Taking snapshot")
        await asyncio.to_thread(interval_stats.make_snapshot)
        print("Snapshot done")


async def retention_loop():
    while True:
        await asyncio.sleep(86400)
        await asyncio.to_thread(cleanup_old_records)