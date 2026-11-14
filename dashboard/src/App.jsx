import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Activity, AlertTriangle, ArrowUp, Globe, Network,
  Play, Radio, RefreshCw, Shield, ShieldAlert, Square, Wifi,
} from 'lucide-react'
import {
  Area, AreaChart, CartesianGrid, ResponsiveContainer, Tooltip,
  XAxis, YAxis, PieChart, Pie, Cell,
} from 'recharts'
import './App.css'

const COLORS = ['#36cfc9', '#688cff', '#b18cff', '#ffb454', '#ff6b81']
const API = ''

function formatTime(value) {
  if (!value) return '—'
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? String(value) : date.toLocaleTimeString()
}

function getEventTitle(event) {
  return event?.event_type || event?.type || event?.event ||
    event?.name || event?.title || 'Security event'
}

function getSeverity(event) {
  return String(event?.severity || event?.level || 'INFO').toUpperCase()
}

function getEventDescription(event) {
  return event?.details || event?.description || event?.message ||
    event?.src_ip || event?.source_ip || 'Security event detected'
}

function App() {
  const [stats, setStats] = useState(null)
  const [events, setEvents] = useState([])
  const [incidents, setIncidents] = useState([])
  const [monitor, setMonitor] = useState(null)
  const [apiOnline, setApiOnline] = useState(false)
  const [wsOnline, setWsOnline] = useState(false)
  const [loading, setLoading] = useState(true)
  const [actionLoading, setActionLoading] = useState(false)
  const [error, setError] = useState('')
  const [history, setHistory] = useState([])

  const refreshData = useCallback(async () => {
    try {
      const [statsRes, eventsRes, incidentsRes, monitorRes, healthRes] =
        await Promise.all([
          fetch(`${API}/api/stats`),
          fetch(`${API}/api/events?limit=50`),
          fetch(`${API}/api/incidents`),
          fetch(`${API}/api/monitor/status`),
          fetch(`${API}/api/health`),
        ])

      if (![statsRes, eventsRes, incidentsRes, monitorRes, healthRes].every(r => r.ok)) {
        throw new Error('One or more API endpoints returned an error')
      }

      const [statsData, eventsData, incidentsData, monitorData] =
        await Promise.all([
          statsRes.json(),
          eventsRes.json(),
          incidentsRes.json(),
          monitorRes.json(),
          healthRes.json(),
        ])

      setStats(statsData)
      setEvents(Array.isArray(eventsData.events) ? eventsData.events.slice().reverse() : [])
      setIncidents(Array.isArray(incidentsData.incidents) ? incidentsData.incidents.slice().reverse() : [])
      setMonitor(monitorData)
      setApiOnline(healthRes.ok)
      setHistory(previous => [
        ...previous.slice(-29),
        {
          time: new Date().toLocaleTimeString(),
          packets: Number(statsData.total_packets) || 0,
        },
      ])
      setError('')
    } catch (err) {
      setApiOnline(false)
      setError(err.message || 'Unable to connect to backend')
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    const initialTimer = setTimeout(() => {
      refreshData()
    }, 0)

    const timer = setInterval(() => {
      refreshData()
    }, 2000)

    return () => {
      clearTimeout(initialTimer)
      clearInterval(timer)
    }
  }, [refreshData])

  useEffect(() => {
    let socket
    let reconnectTimer
    let stopped = false

    const connect = () => {
      if (stopped) return
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:'
      socket = new WebSocket(`${protocol}//${window.location.host}/ws/events`)

      socket.onopen = () => setWsOnline(true)
      socket.onclose = () => {
        setWsOnline(false)
        if (!stopped) reconnectTimer = setTimeout(connect, 3000)
      }
      socket.onerror = () => socket.close()
      socket.onmessage = message => {
        try {
          const payload = JSON.parse(message.data)
          if (payload.type === 'security_alert' && payload.data) {
            setEvents(previous => [payload.data, ...previous].slice(0, 50))
          }
        } catch {
          // Ignore malformed WebSocket messages.
        }
      }
    }

    connect()
    return () => {
      stopped = true
      clearTimeout(reconnectTimer)
      socket?.close()
    }
  }, [])

  const controlMonitoring = async (action) => {
    setActionLoading(true)
    setError('')
    try {
      const response = await fetch(`${API}/api/monitor/${action}`, { method: 'POST' })
      const data = await response.json()
      if (!response.ok || data.status === 'error') {
        throw new Error(data.message || `Could not ${action} monitoring`)
      }
      await refreshData()
    } catch (err) {
      setError(err.message || 'Monitoring control failed')
    } finally {
      setActionLoading(false)
    }
  }

  const protocolData = useMemo(() => {
    const protocols = stats?.protocols || {}
    return Object.entries(protocols)
      .filter(([key, value]) =>
        key !== 'total_packets' && typeof value === 'number' && value > 0)
      .map(([name, value]) => ({ name: name.toUpperCase(), value }))
      .sort((a, b) => b.value - a.value)
  }, [stats])

  const topPorts = stats?.top_ports || []
  const ipStats = Object.entries(stats?.ip_statistics || {}).slice(0, 6)
  const running = Boolean(monitor?.running)

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-icon"><Shield size={23} /></div>
          <div><strong>NETWORK</strong><span>SENTINEL</span></div>
        </div>

        <div className="nav-label">MONITORING</div>
        <div className="nav-item active"><Activity size={18} /> Overview</div>
        <div className="nav-item"><ShieldAlert size={18} /> Threat events</div>
        <div className="nav-item"><Network size={18} /> Network traffic</div>
        <div className="nav-item"><Globe size={18} /> IP intelligence</div>

        <div className="sidebar-bottom">
          <div className="system-card">
            <div className="system-title"><span className="pulse-dot" /> SYSTEM STATUS</div>
            <strong>{apiOnline ? 'Backend connected' : 'Backend offline'}</strong>
            <small>API · {apiOnline ? 'Online' : 'Disconnected'}</small>
            <small>WebSocket · {wsOnline ? 'Connected' : 'Disconnected'}</small>
          </div>
          <div className="sidebar-footer">NETWORK SENTINEL <span>v1.0.0</span></div>
        </div>
      </aside>

      <main className="main-content">
        <header className="topbar">
          <div>
            <div className="eyebrow">SECURITY OPERATIONS CENTER</div>
            <h1>Network Overview</h1>
          </div>
          <div className="topbar-right">
            <div className={`connection ${apiOnline ? 'online' : 'offline'}`}>
              <span /> {apiOnline ? 'API CONNECTED' : 'API OFFLINE'}
            </div>
            <button className="icon-button" onClick={refreshData} title="Refresh data">
              <RefreshCw size={17} />
            </button>
          </div>
        </header>

        {error && <div className="error-banner"><AlertTriangle size={17} /> {error}</div>}

        <section className="monitor-banner">
          <div className="monitor-info">
            <div className={`monitor-icon ${running ? 'running' : ''}`}><Radio size={22} /></div>
            <div>
              <div className="eyebrow">PACKET CAPTURE</div>
              <h2>{running ? 'Live monitoring active' : 'Monitoring stopped'}</h2>
              <p>Interface: <strong>{monitor?.interface || '—'}</strong>
                <span className="separator">·</span>
                Capture duration: <strong>{monitor?.capture_duration ?? '—'}s</strong>
              </p>
            </div>
          </div>
          <div className="monitor-actions">
            {running ? (
              <button className="control-button stop" disabled={actionLoading || !apiOnline}
                onClick={() => controlMonitoring('stop')}>
                <Square size={15} /> Stop monitoring
              </button>
            ) : (
              <button className="control-button start" disabled={actionLoading || !apiOnline}
                onClick={() => controlMonitoring('start')}>
                <Play size={15} /> Start monitoring
              </button>
            )}
          </div>
        </section>

        <section className="stats-grid">
          <StatCard icon={<Activity />} label="TOTAL PACKETS"
            value={stats?.total_packets ?? '—'} note="Captured network packets" />
          <StatCard icon={<ShieldAlert />} label="SECURITY ALERTS"
            value={stats?.total_alerts ?? '—'} note="Events recorded" />
          <StatCard icon={<AlertTriangle />} label="INCIDENTS"
            value={stats?.total_incidents ?? '—'} note="Recorded incidents" />
          <StatCard icon={<Wifi />} label="MONITOR STATUS"
            value={loading ? '…' : running ? 'ACTIVE' : 'IDLE'}
            note={running ? 'Packet capture running' : 'Capture not running'}
            status={running} />
        </section>

        <section className="content-grid">
          <div className="panel traffic-panel">
            <PanelHeading title="Network traffic" subtitle="Packet count snapshots · refreshes every 2 seconds" />
            <div className="chart-area">
              {history.length > 1 ? (
                <ResponsiveContainer width="100%" height="100%">
                  <AreaChart data={history}>
                    <defs>
                      <linearGradient id="packetGradient" x1="0" y1="0" x2="0" y2="1">
                        <stop offset="0%" stopColor="#36cfc9" stopOpacity={0.3} />
                        <stop offset="95%" stopColor="#36cfc9" stopOpacity={0} />
                      </linearGradient>
                    </defs>
                    <CartesianGrid stroke="#202d40" strokeDasharray="3 3" vertical={false} />
                    <XAxis dataKey="time" tick={{ fill: '#7e8da4', fontSize: 10 }}
                      tickLine={false} axisLine={false} minTickGap={30} />
                    <YAxis tick={{ fill: '#7e8da4', fontSize: 10 }}
                      tickLine={false} axisLine={false} width={45} />
                    <Tooltip contentStyle={{ background: '#111d2e', border: '1px solid #26364d', borderRadius: 8 }}
                      labelStyle={{ color: '#dce7f5' }} />
                    <Area type="monotone" dataKey="packets" stroke="#36cfc9"
                      strokeWidth={2} fill="url(#packetGradient)" />
                  </AreaChart>
                </ResponsiveContainer>
              ) : <EmptyState text="Waiting for packet statistics…" />}
            </div>
          </div>

          <div className="panel protocol-panel">
            <PanelHeading title="Protocol distribution" subtitle="Captured packets by protocol" />
            {protocolData.length ? (
              <>
                <div className="donut-wrap">
                  <ResponsiveContainer width="100%" height="100%">
                    <PieChart>
                      <Pie data={protocolData} dataKey="value" nameKey="name"
                        innerRadius={58} outerRadius={83} paddingAngle={4} stroke="none">
                        {protocolData.map((entry, index) => (
                          <Cell key={entry.name} fill={COLORS[index % COLORS.length]} />
                        ))}
                      </Pie>
                      <Tooltip contentStyle={{ background: '#111d2e', border: '1px solid #26364d', borderRadius: 8 }} />
                    </PieChart>
                  </ResponsiveContainer>
                  <div className="donut-center"><strong>{stats?.total_packets ?? 0}</strong><span>PACKETS</span></div>
                </div>
                <div className="legend">
                  {protocolData.map((item, index) => (
                    <div className="legend-row" key={item.name}>
                      <span className="legend-name"><i style={{ background: COLORS[index % COLORS.length] }} />{item.name}</span>
                      <strong>{item.value}</strong>
                    </div>
                  ))}
                </div>
              </>
            ) : <EmptyState text="No protocol data available yet." />}
          </div>
        </section>

        <section className="content-grid lower-grid">
          <div className="panel events-panel">
            <PanelHeading title="Recent security events" subtitle="Latest events from the detection engine">
              <span className="live-label"><i /> LIVE</span>
            </PanelHeading>
            {events.length ? (
              <div className="event-list">
                {events.slice(0, 8).map((event, index) => (
                  <div className="event-row" key={event.id || `${getEventTitle(event)}-${index}`}>
                    <div className={`severity-icon ${getSeverity(event).toLowerCase()}`}>
                      <AlertTriangle size={16} />
                    </div>
                    <div className="event-main">
                      <strong>{getEventTitle(event)}</strong>
                      <span>{getEventDescription(event)}</span>
                    </div>
                    <div className="event-meta">
                      <span className={`severity-badge ${getSeverity(event).toLowerCase()}`}>
                        {getSeverity(event)}
                      </span>
                      <small>{formatTime(event.timestamp || event.time || event.created_at)}</small>
                    </div>
                  </div>
                ))}
              </div>
            ) : <EmptyState text="No security events recorded." />}
          </div>

          <div className="panel ports-panel">
            <PanelHeading title="Top destination ports" subtitle="Most active ports by packet count" />
            {topPorts.length ? topPorts.slice(0, 7).map((item, index) => (
              <div className="port-row" key={item.port}>
                <span className="port-rank">{String(index + 1).padStart(2, '0')}</span>
                <strong>:{item.port}</strong>
                <div className="port-bar"><i style={{
                  width: `${Math.max(3, (item.packets / Math.max(...topPorts.map(p => p.packets), 1)) * 100)}%`
                }} /></div>
                <span className="port-count">{item.packets}</span>
              </div>
            )) : <EmptyState text="No port statistics available." />}
          </div>
        </section>

        <section className="content-grid lower-grid">
          <div className="panel">
            <PanelHeading title="Recent incidents" subtitle="Latest recorded security incidents" />
            {incidents.length ? incidents.slice(0, 5).map((incident, index) => (
              <div className="simple-row" key={incident.id || index}>
                <ShieldAlert size={16} />
                <div><strong>{getEventTitle(incident)}</strong><small>{getEventDescription(incident)}</small></div>
                <span className={`severity-badge ${getSeverity(incident).toLowerCase()}`}>
                  {getSeverity(incident)}
                </span>
              </div>
            )) : <EmptyState text="No incidents recorded." />}
          </div>

          <div className="panel">
            <PanelHeading title="IP activity" subtitle="Recent IP statistics from the engine" />
            {ipStats.length ? ipStats.map(([ip, data]) => (
              <div className="simple-row" key={ip}>
                <Globe size={16} />
                <div><strong>{ip}</strong><small>{JSON.stringify(data)}</small></div>
              </div>
            )) : <EmptyState text="No IP statistics available." />}
          </div>
        </section>

        <footer className="page-footer">
          <span>NETWORK SENTINEL <b>·</b> SECURITY MONITORING</span>
          <span><ArrowUp size={12} /> API polling · 2s <b>·</b> WebSocket {wsOnline ? 'connected' : 'disconnected'}</span>
        </footer>
      </main>
    </div>
  )
}

function StatCard({ icon, label, value, note, status }) {
  return (
    <div className="stat-card">
      <div className="stat-top"><span>{label}</span><i>{icon}</i></div>
      <strong className={status ? 'active-value' : ''}>{value}</strong>
      <small>{note}</small>
    </div>
  )
}

function PanelHeading({ title, subtitle, children }) {
  return (
    <div className="panel-heading">
      <div><h3>{title}</h3><p>{subtitle}</p></div>
      {children}
    </div>
  )
}

function EmptyState({ text }) {
  return <div className="empty-state">{text}</div>
}

export default App
