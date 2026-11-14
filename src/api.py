import asyncio
from contextlib import suppress

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from scapy.all import AsyncSniffer


from src import main as engine


app = FastAPI(
    title="Network Sentinel API",
    description="Real-time network threat monitoring platform",
    version="1.0.0"
)

sniffer = None
event_loop = None
connected_clients = set()


def publish_event(event):
    """Called by the packet-processing thread."""

    if event_loop and event_loop.is_running():
        event_loop.call_soon_threadsafe(
            broadcast_event,
            event
        )


def broadcast_event(event):
    """Push events into connected WebSocket queues."""

    for queue in list(connected_clients):
        if queue.full():
            with suppress(asyncio.QueueEmpty):
                queue.get_nowait()

        queue.put_nowait(event)


@app.on_event("startup")
async def startup():
    global event_loop

    event_loop = asyncio.get_running_loop()
    engine.event_logger.add_listener(publish_event)

    print("NETWORK SENTINEL API READY")


@app.on_event("shutdown")
async def shutdown():
    await stop_capture()
    engine.event_logger.remove_listener(publish_event)


@app.get("/")
async def root():
    return {
        "name": "Network Sentinel",
        "status": "online",
        "version": "1.0.0",
        "documentation": "/docs"
    }


@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "monitoring": bool(sniffer and sniffer.running)
    }


@app.get("/api/stats")
async def get_stats():
    return {
        "total_packets": engine.traffic_stats["total_packets"],
        "protocols": dict(engine.traffic_stats),
        "tcp_flags": dict(engine.tcp_flag_stats),
        "top_ports": [
            {"port": port, "packets": count}
            for port, count in engine.port_stats.most_common(10)
        ],
        "ip_statistics": {
            ip: dict(stats)
            for ip, stats in engine.ip_stats.items()
        },
        "total_alerts": len(engine.event_logger.events),
        "total_incidents": len(engine.event_logger.incidents)
    }


@app.get("/api/events")
async def get_events(limit: int = 100):
    limit = max(1, min(limit, 500))

    return {
        "total": len(engine.event_logger.events),
        "events": engine.event_logger.events[-limit:]
    }


@app.get("/api/incidents")
async def get_incidents():
    return {
        "total": len(engine.event_logger.incidents),
        "incidents": engine.event_logger.incidents[-100:]
    }


@app.get("/api/monitor/status")
async def monitor_status():
    return {
        "running": bool(sniffer and sniffer.running),
        "interface": engine.INTERFACE,
        "capture_duration": engine.CAPTURE_DURATION
    }


async def stop_capture():
    global sniffer

    if sniffer and sniffer.running:
        current_sniffer = sniffer
        sniffer = None
        current_sniffer.stop(join=True)

    return {"status": "stopped"}


@app.post("/api/monitor/start")
async def start_capture():
    global sniffer

    if sniffer and sniffer.running:
        return {
            "status": "already_running",
            "interface": engine.INTERFACE
        }

    try:
        sniffer = AsyncSniffer(
            iface=engine.INTERFACE,
            prn=engine.process_packet,
            store=False
        )

        sniffer.start()

        return {
            "status": "started",
            "interface": engine.INTERFACE
        }

    except Exception as error:
        sniffer = None

        return {
            "status": "error",
            "message": str(error)
        }


@app.post("/api/monitor/stop")
async def stop_monitor():
    await stop_capture()

    return {"status": "stopped"}


@app.websocket("/ws/events")
async def websocket_events(websocket: WebSocket):
    await websocket.accept()

    queue = asyncio.Queue(maxsize=100)
    connected_clients.add(queue)

    try:
        await websocket.send_json({
            "type": "connection",
            "message": "Connected to Network Sentinel"
        })

        while True:
            event = await queue.get()

            await websocket.send_json({
                "type": "security_alert",
                "data": event
            })

    except WebSocketDisconnect:
        pass

    finally:
        connected_clients.discard(queue)
