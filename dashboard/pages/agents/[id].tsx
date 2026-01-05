import { useState, useEffect } from 'react'
import { useRouter } from 'next/router'
import Link from 'next/link'

interface Event {
  id: string
  event_type: string
  ts: string
  event_hash: string
  metadata_json: any
}

interface Summary {
  event_type_counts: Record<string, number>
  top_tools: Array<{ tool_name: string; count: number }>
  top_data_sources: Array<{ identifier: string; count: number }>
}

interface VerificationResult {
  valid: boolean
  total_events: number
  first_bad_seq: number | null
  signature_valid: boolean | null
}

export default function AgentDetail() {
  const router = useRouter()
  const { id } = router.query
  const [events, setEvents] = useState<Event[]>([])
  const [summary, setSummary] = useState<Summary | null>(null)
  const [verification, setVerification] = useState<VerificationResult | null>(null)
  const [loading, setLoading] = useState(true)
  const [verifying, setVerifying] = useState(false)

  useEffect(() => {
    if (!id) return

    const apiKey = sessionStorage.getItem('aapm_api_key')
    const endpoint = sessionStorage.getItem('aapm_endpoint') || 'http://localhost:8000'

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

    // Fetch summary
    fetch(`${endpoint}/v1/agents/${id}/summary`, {
      headers: { 'X-API-Key': apiKey }
    })
      .then(res => res.json())
      .then(data => setSummary(data))
      .finally(() => setLoading(false))
  }, [id, router])

  const handleVerify = async () => {
    if (!id) return

    setVerifying(true)
    const apiKey = sessionStorage.getItem('aapm_api_key')
    const endpoint = sessionStorage.getItem('aapm_endpoint') || 'http://localhost:8000'

    try {
      const res = await fetch(`${endpoint}/v1/verify/chain?agent_id=${id}`, {
        headers: { 'X-API-Key': apiKey }
      })
      const data = await res.json()
      setVerification(data)
    } catch (err) {
      console.error('Verification error:', err)
    } finally {
      setVerifying(false)
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
        <button
          className="btn btn-primary"
          onClick={handleVerify}
          disabled={verifying}
        >
          {verifying ? 'Verifying...' : 'Verify Chain'}
        </button>
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
          {summary.top_tools.length > 0 && (
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
              </tr>
            </thead>
            <tbody>
              {events.map(event => (
                <tr key={event.id}>
                  <td>{new Date(event.ts).toLocaleString()}</td>
                  <td>{event.event_type}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '11px' }}>
                    {event.event_hash.substring(0, 16)}...
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}

