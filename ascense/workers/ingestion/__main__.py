import asyncio
from ascense.workers.ingestion.worker import run_normalization_worker

asyncio.run(run_normalization_worker())
