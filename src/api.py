import asyncio
import os
import secrets
from contextlib import suppress
from ipaddress import IPv4Address
from typing import Literal

from fastapi import (
    FastAPI,
    WebSocket,
    WebSocketDisconnect,
    HTTPException,
    Header
)
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field
from scapy.all import IP, TCP, UDP, ICMP

from src import main as engine


app = FastAPI(
    title="Network Sentinel API",
    description="Real-time network threat monitoring platform",
    version="1.0.0"
)

connected_clients = set()
event_loop = None


# ==========================================
# SENSOR DATA MODELS
# ==========================================

class SensorPacket(BaseModel):
    source_ip: IPv4Address
    destination_ip: IPv4Address
    protocol: Literal["TCP", "UDP", "ICMP", "OTHER"]

    source_port: int | None = Field(default=None, ge=0, le=65535)
    destination_port: int | None = Field(default=None, ge=0, le=65535)

    tcp_flags: list[
        Literal["FIN", "SYN", "RST", "PSH", "ACK", "URG"]
    ] = Field(default_factory=list, max_length=6)

    icmp_type: int | None = Field(default=None, ge=0, le=255)
    icmp_code: int | None = Field(default=None, ge=0, le=255)


class SensorBatch(BaseModel):
    packets: list[SensorPacket] = Field(min_length=1, max_length=200)


# ==========================================
# EVENT BROADCASTING
# ==========================================

def publish_event(event):
    if event_loop and event_loop.is_running():
        event_loop.call_soon_threadsafe(
            broadcast_event,
            event
        )


def broadcast_event(event):
    for queue in list(connected_clients):
        if queue.full():
            with suppress(asyncio.QueueEmpty):
                queue.get_nowait()

        queue.put_nowait(event)


# ==========================================
# STARTUP / SHUTDOWN
# ==========================================

@app.on_event("startup")
async def startup():
    global event_loop

    event_loop = asyncio.get_running_loop()
    engine.event_logger.add_listener(publish_event)

    print("NETWORK SENTINEL API READY")
    print("REMOTE PACKET CAPTURE DISABLED")
    print("WAITING FOR AUTHENTICATED SENSOR")


@app.on_event("shutdown")
async def shutdown():
    engine.event_logger.remove_listener(publish_event)


# ==========================================
# HEALTH
# ==========================================

@app.get("/api/health")
async def health():
    return {
        "status": "healthy",
        "monitoring": True,
        "capture_mode": "remote_sensor"
    }


# ==========================================
# STATS
# ==========================================

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


# ==========================================
# EVENTS
# ==========================================

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


# ==========================================
# MONITOR STATUS
# ==========================================

@app.get("/api/monitor/status")
async def monitor_status():
    return {
        "running": True,
        "interface": "remote sensor",
        "capture_duration": engine.CAPTURE_DURATION,
        "capture_mode": "remote_sensor"
    }


@app.post("/api/monitor/start")
async def start_capture():
    return {
        "status": "disabled",
        "message": "Start the local sensor on your WSL machine."
    }


@app.post("/api/monitor/stop")
async def stop_monitor():
    return {
        "status": "disabled",
        "message": "Stop the local sensor on your WSL machine."
    }


# ==========================================
# AUTHENTICATED SENSOR INGESTION
# ==========================================

@app.post("/api/sensor/packets")
def receive_sensor_packets(
    batch: SensorBatch,
    x_sensor_key: str = Header(default="", alias="X-Sensor-Key")
):
    expected_key = os.getenv("SENSOR_API_KEY", "")

    if not expected_key:
        raise HTTPException(
            status_code=503,
            detail="Sensor authentication is not configured"
        )

    if not secrets.compare_digest(x_sensor_key, expected_key):
        raise HTTPException(
            status_code=401,
            detail="Invalid sensor authentication"
        )

    flag_values = {
        "FIN": 0x01,
        "SYN": 0x02,
        "RST": 0x04,
        "PSH": 0x08,
        "ACK": 0x10,
        "URG": 0x20
    }

    processed = 0

    for item in batch.packets:
        packet = IP(
            src=str(item.source_ip),
            dst=str(item.destination_ip)
        )

        if item.protocol == "TCP":
            flags = sum(
                flag_values[flag]
                for flag in item.tcp_flags
            )

            packet = packet / TCP(
                sport=item.source_port or 0,
                dport=item.destination_port or 0,
                flags=flags
            )

        elif item.protocol == "UDP":
            packet = packet / UDP(
                sport=item.source_port or 0,
                dport=item.destination_port or 0
            )

        elif item.protocol == "ICMP":
            packet = packet / ICMP(
                type=item.icmp_type if item.icmp_type is not None else 8,
                code=item.icmp_code if item.icmp_code is not None else 0
            )

        engine.process_packet(packet)
        processed += 1

    return {
        "status": "received",
        "packets_processed": processed
    }


# ==========================================
# WEBSOCKET
# ==========================================

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


# ==========================================
# FRONTEND
# ==========================================

app.mount(
    "/",
    StaticFiles(directory="dashboard/dist", html=True),
    name="dashboard"
)
