import asyncio

from ascense.workers.detection.worker import run_worker

asyncio.run(run_worker())
