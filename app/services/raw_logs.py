import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging

from pymongo.errors import PyMongoError
from starlette.concurrency import run_in_threadpool

from app.schemas.log import LogCreate
from app.services.logs import store_logs

logger = logging.getLogger("uvicorn.error.siem.raw_logs")


class RawLogReceiver(asyncio.DatagramProtocol):
    def __init__(self):
        self.pending: asyncio.Queue[LogCreate] = asyncio.Queue(maxsize=128)

    def datagram_received(self, data, address):
        message = data.decode("utf-8", errors="replace").strip()
        if not message or self.pending.full():
            return
        source_ip, source_port = address[:2]
        self.pending.put_nowait(LogCreate(
            timestamp=datetime.now(timezone.utc),
            source=source_ip,
            message=message,
            attributes={"source_ip": source_ip, "source_port": source_port, "protocol": "UDP"},
        ))

    async def store_pending(self, database):
        while True:
            events = [await self.pending.get()]
            while not self.pending.empty():
                events.append(self.pending.get_nowait())
            try:
                await run_in_threadpool(store_logs, database, events)
            except PyMongoError:
                logger.warning("MongoDB write failed for a batch of %d UDP logs", len(events))
            finally:
                for _ in events:
                    self.pending.task_done()


@asynccontextmanager
async def listen_for_raw_logs(database, host, port):
    transport, receiver = await asyncio.get_running_loop().create_datagram_endpoint(
        RawLogReceiver, local_addr=(host, port),
    )
    worker = asyncio.create_task(receiver.store_pending(database))
    try:
        logger.info("Listening for raw UDP logs on %s:%s", host, port)
        yield
    finally:
        transport.close()
        try:
            await receiver.pending.join()
        finally:
            worker.cancel()
            await asyncio.gather(worker, return_exceptions=True)
