import asyncio
from src.history import make_snapshot
from storage.retention import cleanup_old_records


async def snapshot_loop():
    while True:
        await asyncio.sleep(60)
        await asyncio.to_thread(make_snapshot)


async def retention_loop():
    while True:
        await asyncio.sleep(86400)
        await asyncio.to_thread(cleanup_old_records)