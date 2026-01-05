import { useState, useEffect } from 'react'
import { useRouter } from 'next/router'
import Link from 'next/link'

interface Event {
  id: string
  event_type: string
  ts?: string
  server_timestamp?: string
  timestamp?: string
  event_hash: string
  chain_hash?: string
  prev_chain_hash?: string
  metadata_json?: any
  action?: any
  data_sources?: any
  outcome?: any
}

interface Summary {
  event_type_counts: Record<string, number>
  top_tools: Array<{ tool_name: string; count: number }>
  total_events?: number
}

interface Metrics {
  total_events: number
  chain_length: number
  first_event_time: string | null
  last_event_time: string | null
  last_verification_time: string | null
  chain_status: string
}

interface VerificationResult {
  valid: boolean
  total_events: number
  first_bad_seq: number | null
  signature_valid: boolean | null
  chain_intact?: boolean
  status?: string
}

export default function AgentDetail() {
  const router = useRouter()
  const { id } = router.query
  const [events, setEvents] = useState<Event[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [metrics, setMetrics] = useState<Metrics | null>(null)
  const [verification, setVerification] = useState<VerificationResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)
  const [downloading, setDownloading] = useState(false)

  const getApiConfig = () => {
    const apiKey = sessionStorage.getItem('aapm_api_key')
    const endpoint = sessionStorage.getItem('aapm_endpoint') || 'http://localhost:8000'
    return { apiKey, endpoint }
  }

  useEffect(() => {
    if (!id) return

    const { apiKey, endpoint } = getApiConfig()

    if (!apiKey) {
      router.push('/')
      return
    }

    // Fetch events
    fetch(`${endpoint}/v1/agents/${id}/events?limit=100`, {
      headers: { 'X-API-Key': apiKey }
    })
      .then(res => res.json())
      .then(data => setEvents(data.events || []))
      .catch(err => console.error('Error fetching events:', err))

    // Fetch summary
    fetch(`${endpoint}/v1/agents/${id}/summary`, {
      headers: { 'X-API-Key': apiKey }
    })
      .then(res => res.json())
      .then(data => setSummary(data))
      .catch(err => console.error('Error fetching summary:', err))

    // Fetch metrics
    fetch(`${endpoint}/v1/agents/${id}/metrics`, {
      headers: { 'X-API-Key': apiKey }
    })
      .then(res => res.json())
      .then(data => setMetrics(data))
      .catch(err => console.error('Error fetching metrics:', err))
      .finally(() => setLoading(false))
  }, [id, router])

  const handleVerify = async () => {
    if (!id) return

    setVerifying(true)
    const { apiKey, endpoint } = getApiConfig()

    try {
      const res = await fetch(`${endpoint}/v1/verify/chain?agent_id=${id}`, {
        headers: { 'X-API-Key': apiKey || '' }
      })
      const data = await res.json()
      setVerification(data)
      
      // Refresh metrics after verification
      const metricsRes = await fetch(`${endpoint}/v1/agents/${id}/metrics`, {
        headers: { 'X-API-Key': apiKey || '' }
      })
      const metricsData = await metricsRes.json()
      setMetrics(metricsData)
    } catch (err) {
      console.error('Verification error:', err)
    } finally {
      setVerifying(false)
    }
  }

  const handleDownloadProof = async () => {
    if (!id) return

    setDownloading(true)
    const { apiKey, endpoint } = getApiConfig()

    try {
      const res = await fetch(`${endpoint}/v1/agents/${id}/proof`, {
        headers: { 'X-API-Key': apiKey || '' }
      })
      const proof = await res.json()
      
      // Create and download file
      const blob = new Blob([JSON.stringify(proof, null, 2)], { type: 'application/json' })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url
      a.download = `aapm-proof-${id}-${new Date().toISOString().split('T')[0]}.json`
      document.body.appendChild(a)
      a.click()
      document.body.removeChild(a)
      URL.revokeObjectURL(url)
    } catch (err) {
      console.error('Download error:', err)
      alert('Failed to download proof. Please try again.')
    } finally {
      setDownloading(false)
    }
  }

  const getStatusBadgeClass = (status: string | undefined) => {
    if (!status) return 'badge'
    switch (status.toLowerCase()) {
      case 'valid':
      case 'verified':
        return 'badge badge-valid'
      case 'broken':
      case 'tampered':
      case 'invalid':
        return 'badge badge-invalid'
      default:
        return 'badge badge-unknown'
    }
  }

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading agent details...</div>
      </div>
    )
  }

  return (
    <div className="container">
      <div className="header">
        <h1>Agent Details</h1>
        <Link href="/agents" style={{ color: '#666', textDecoration: 'none' }}>
          ← Back to Agents
        </Link>
      </div>

      {/* Metrics Dashboard */}
      {metrics && (
        <div className="card">
          <h2>Metrics</h2>
          <div className="metrics-grid">
            <div className="metric-item">
              <div className="metric-value">{metrics.total_events}</div>
              <div className="metric-label">Total Events</div>
            </div>
            <div className="metric-item">
              <div className="metric-value">{metrics.chain_length}</div>
              <div className="metric-label">Chain Length</div>
            </div>
            <div className="metric-item">
              <div className={getStatusBadgeClass(metrics.chain_status)} style={{ fontSize: '16px', padding: '8px 16px' }}>
                {metrics.chain_status || 'Unknown'}
              </div>
              <div className="metric-label">Chain Status</div>
            </div>
            <div className="metric-item">
              <div className="metric-value" style={{ fontSize: '14px' }}>
                {metrics.last_verification_time 
                  ? new Date(metrics.last_verification_time).toLocaleString()
                  : 'Never'}
              </div>
              <div className="metric-label">Last Verified</div>
            </div>
          </div>
        </div>
      )}

      {/* Verification Status */}
      <div className="card">
        <h2>Chain Integrity</h2>
        {verification ? (
          <div>
            <p>
              Status:{' '}
              <span className={`badge ${verification.valid ? 'badge-valid' : 'badge-invalid'}`}>
                {verification.valid ? 'Valid' : 'Invalid'}
              </span>
            </p>
            <p>Total Events: {verification.total_events}</p>
            {verification.first_bad_seq && (
              <p style={{ color: '#721c24' }}>
                Chain broken at sequence: {verification.first_bad_seq}
              </p>
            )}
            {verification.signature_valid !== null && (
              <p>Signature Valid: {verification.signature_valid ? 'Yes' : 'No'}</p>
            )}
          </div>
        ) : (
          <p>Click below to verify chain integrity.</p>
        )}
        <div style={{ marginTop: '16px', display: 'flex', gap: '12px' }}>
          <button
            className="btn btn-primary"
            onClick={handleVerify}
            disabled={verifying}
          >
            {verifying ? 'Verifying...' : 'Verify Chain'}
          </button>
          <button
            className="btn btn-secondary"
            onClick={handleDownloadProof}
            disabled={downloading}
            title="Download cryptographic proof for offline verification"
          >
            {downloading ? 'Downloading...' : '📥 Download Proof'}
          </button>
        </div>
      </div>

      {/* Summary */}
      {summary && (
        <div className="card">
          <h2>Summary</h2>
          <div style={{ marginBottom: '20px' }}>
            <h3>Event Types</h3>
            <ul>
              {Object.entries(summary.event_type_counts).map(([type, count]) => (
                <li key={type}>
                  {type}: {count}
                </li>
              ))}
            </ul>
          </div>
          {summary.top_tools && summary.top_tools.length > 0 && (
            <div style={{ marginBottom: '20px' }}>
              <h3>Top Tools</h3>
              <ul>
                {summary.top_tools.map((tool, i) => (
                  <li key={i}>
                    {tool.tool_name}: {tool.count}
                  </li>
                ))}
              </ul>
            </div>
          )}
        </div>
      )}

      {/* Events */}
      <div className="card">
        <h2>Recent Events</h2>
        {events.length === 0 ? (
          <p>No events found.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Time</th>
                <th>Type</th>
                <th>Event Hash</th>
                <th>Chain Hash</th>
              </tr>
            </thead>
            <tbody>
              {events.map(event => (
                <tr key={event.id}>
                  <td>{new Date(event.ts || event.server_timestamp || event.timestamp || '').toLocaleString()}</td>
                  <td>{event.event_type}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>
                    {event.event_hash ? event.event_hash.substring(0, 16) + '...' : '-'}
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>
                    {event.chain_hash ? event.chain_hash.substring(0, 16) + '...' : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>

      <style jsx>{`
        .metrics-grid {
          display: grid;
          grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
          gap: 20px;
          margin-top: 16px;
        }
        .metric-item {
          text-align: center;
          padding: 16px;
          background: #f8f9fa;
          border-radius: 8px;
        }
        .metric-value {
          font-size: 24px;
          font-weight: bold;
          color: #333;
        }
        .metric-label {
          font-size: 12px;
          color: #666;
          margin-top: 4px;
          text-transform: uppercase;
        }
        .badge-unknown {
          background: #e9ecef;
          color: #495057;
        }
      `}</style>
    </div>
  )
}
