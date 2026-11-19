import asyncio
from contextlib import asynccontextmanager
from datetime import datetime, timezone
import logging
import re

from pymongo.errors import PyMongoError
from starlette.concurrency import run_in_threadpool

from app.schemas.log import LogCreate, LogLevel
from app.services.logs import store_logs

logger = logging.getLogger("uvicorn.error.siem.raw_logs")
RFC5424 = re.compile(
    r"<(?P<pri>[0-9]{1,3})>1 (?P<timestamp>\S+) (?P<host>[!-~]{1,255}) "
    r"(?P<app>\S+) (?P<pid>\S+) (?P<msgid>\S+) "
    r"(?P<structured_data>-|(?:\[(?:[^\]\\\r\n]|\\.)*\])+)(?: (?P<message>.*))?",
    re.DOTALL,
)
RFC3164 = re.compile(
    r"<(?P<pri>[0-9]{1,3})>(?P<timestamp>(?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)"
    r" [ 0-9][0-9] [0-9]{2}:[0-9]{2}:[0-9]{2}) (?P<host>[!-~]{1,255}) "
    r"(?P<app>[^\s:\[\]]+)(?:\[(?P<pid>[0-9]+)\])?:\s*(?P<message>.*)",
    re.DOTALL,
)
SYSLOG_LEVELS = (
    LogLevel.CRITICAL, LogLevel.CRITICAL, LogLevel.CRITICAL, LogLevel.ERROR,
    LogLevel.WARNING, LogLevel.INFO, LogLevel.INFO, LogLevel.DEBUG,
)


def parse_raw_log(
    message: str, source: str, received_at: datetime, attributes: dict,
) -> LogCreate:
    fields = {"timestamp": received_at, "source": source, "message": message}
    for format_name, pattern in (("rfc5424", RFC5424), ("rfc3164", RFC3164)):
        match = pattern.fullmatch(message)
        if match is None:
            continue
        header = match.groupdict()
        priority = int(header["pri"])
        if priority > 191:
            break

        if format_name == "rfc5424" and header["timestamp"] != "-":
            try:
                timestamp = datetime.fromisoformat(header["timestamp"])
                if timestamp.utcoffset() is None:
                    break
                fields["timestamp"] = timestamp.astimezone(timezone.utc)
            except (ValueError, OverflowError):
                break

        severity = priority % 8
        attributes.update(
            syslog_format=format_name, syslog_facility=priority // 8,
            syslog_severity=severity, raw_message=message,
        )
        for key in ("timestamp", "host", "app", "pid", "msgid", "structured_data"):
            value = header.get(key)
            if value and value != "-":
                attributes[f"syslog_{key}"] = value
        fields["level"] = SYSLOG_LEVELS[severity]
        fields["message"] = (header["message"] or "").strip() or message
        break
    return LogCreate(**fields, attributes=attributes)


class RawLogReceiver(asyncio.DatagramProtocol):
    def __init__(self):
        self.pending: asyncio.Queue[LogCreate] = asyncio.Queue(maxsize=128)

    def datagram_received(self, data, address):
        message = data.decode("utf-8", errors="replace").strip()
        if not message or self.pending.full():
            return
        source_ip, source_port = address[:2]
        self.pending.put_nowait(parse_raw_log(
            message, source_ip, datetime.now(timezone.utc),
            {"source_ip": source_ip, "source_port": source_port, "protocol": "UDP"},
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
