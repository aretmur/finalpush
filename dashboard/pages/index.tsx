import { useState, useEffect } from 'react'
import { useRouter } from 'next/router'

export default function Home() {
  const [apiKey, setApiKey] = useState('')
  const [orgId, setOrgId] = useState('')
  const [endpoint, setEndpoint] = useState('http://localhost:8000')
  const router = useRouter()

  const handleLogin = (e: React.FormEvent) => {
    e.preventDefault()
    if (apiKey && orgId) {
      // Store in sessionStorage (simple auth for MVP)
      sessionStorage.setItem('aapm_api_key', apiKey)
      sessionStorage.setItem('aapm_org_id', orgId)
      sessionStorage.setItem('aapm_endpoint', endpoint)
      router.push('/agents')
    }
  }

  return (
    <div className="container">
      <div className="header">
        <h1>AAPM Dashboard</h1>
        <p>Agent Activity & Permission Monitor</p>
      </div>

      <div className="card">
        <h2>Login</h2>
        <form onSubmit={handleLogin}>
          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', marginBottom: '8px' }}>
              API Key
            </label>
            <input
              type="password"
              value={apiKey}
              onChange={(e) => setApiKey(e.target.value)}
              style={{
                width: '100%',
                padding: '8px',
                border: '1px solid #ddd',
                borderRadius: '4px'
              }}
              required
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', marginBottom: '8px' }}>
              Organization ID
            </label>
            <input
              type="text"
              value={orgId}
              onChange={(e) => setOrgId(e.target.value)}
              style={{
                width: '100%',
                padding: '8px',
                border: '1px solid #ddd',
                borderRadius: '4px'
              }}
              required
            />
          </div>

          <div style={{ marginBottom: '16px' }}>
            <label style={{ display: 'block', marginBottom: '8px' }}>
              Endpoint
            </label>
            <input
              type="text"
              value={endpoint}
              onChange={(e) => setEndpoint(e.target.value)}
              style={{
                width: '100%',
                padding: '8px',
                border: '1px solid #ddd',
                borderRadius: '4px'
              }}
            />
          </div>

          <button type="submit" className="btn btn-primary">
            Login
          </button>
        </form>
      </div>
    </div>
  )
}

