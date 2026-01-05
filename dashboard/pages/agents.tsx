import { useState, useEffect } from 'react'
import { useRouter } from 'next/router'
import Link from 'next/link'

interface Agent {
  id: string
  name: string | null
  framework: string
  assistant_id: string | null
  created_at: string
}

export default function Agents() {
  const router = useRouter()
  const [agents, setAgents] = useState<Agent[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const apiKey = sessionStorage.getItem('aapm_api_key')
    const endpoint = sessionStorage.getItem('aapm_endpoint') || 'http://localhost:8000'

    if (!apiKey) {
      router.push('/')
      return
    }

    fetch(`${endpoint}/v1/agents`, {
      headers: {
        'X-API-Key': apiKey
      }
    })
      .then(res => {
        if (!res.ok) throw new Error('Failed to fetch agents')
        return res.json()
      })
      .then(data => {
        setAgents(data.agents || [])
        setLoading(false)
      })
      .catch(err => {
        setError(err.message)
        setLoading(false)
      })
  }, [router])

  if (loading) {
    return (
      <div className="container">
        <div className="loading">Loading agents...</div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="container">
        <div className="error">Error: {error}</div>
      </div>
    )
  }

  return (
    <div className="container">
      <div className="header">
        <h1>Agents</h1>
        <Link href="/" style={{ color: '#666', textDecoration: 'none' }}>
          ← Back
        </Link>
      </div>

      <div className="card">
        {agents.length === 0 ? (
          <p>No agents found.</p>
        ) : (
          <table className="table">
            <thead>
              <tr>
                <th>Name</th>
                <th>Framework</th>
                <th>Assistant ID</th>
                <th>Created</th>
                <th>Actions</th>
              </tr>
            </thead>
            <tbody>
              {agents.map(agent => (
                <tr key={agent.id}>
                  <td>{agent.name || 'Unnamed'}</td>
                  <td>{agent.framework}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: '12px' }}>
                    {agent.assistant_id || agent.id}
                  </td>
                  <td>{new Date(agent.created_at).toLocaleString()}</td>
                  <td>
                    <Link href={`/agents/${agent.id}`}>
                      <button className="btn btn-secondary">View</button>
                    </Link>
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

