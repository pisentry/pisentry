export interface Host {
  name: string
  created_at: string
  last_seen: string
  reported_as?: string
  status: 'ok' | 'quiet' | 'waiting'
  events_24h: number
}

export interface EventRow {
  host: string
  id: string
  time: string
  category: string
  severity: string
  rule_id?: string
  summary: string
}

export interface CategoryCount {
  category: string
  events: number
  hosts: number
  worst: string
}

const KEY = 'pisentry-panel-token'

export function getToken(): string {
  try {
    return sessionStorage.getItem(KEY) ?? ''
  } catch {
    return ''
  }
}

export function setToken(t: string) {
  try {
    if (t) sessionStorage.setItem(KEY, t)
    else sessionStorage.removeItem(KEY)
  } catch {
    /* storage blocked: the token lives only in memory */
  }
  memory = t
}

let memory = getToken()

export class Unauthorized extends Error {}

export async function get<T>(path: string, params: Record<string, string> = {}): Promise<T> {
  const q = new URLSearchParams(Object.entries(params).filter(([, v]) => v !== ''))
  const url = '/api/' + path + (q.toString() ? '?' + q : '')
  const res = await fetch(url, { headers: { Authorization: 'Bearer ' + memory }, cache: 'no-store' })
  if (res.status === 401) throw new Unauthorized()
  if (!res.ok) {
    const body = await res.json().catch(() => ({}))
    throw new Error(body.error ?? res.statusText)
  }
  return res.json() as Promise<T>
}

export function ago(iso: string): string {
  if (!iso || iso.startsWith('0001')) return 'never'
  const s = Math.max(0, (Date.now() - Date.parse(iso)) / 1000)
  if (s < 60) return `${Math.round(s)}s ago`
  if (s < 3600) return `${Math.round(s / 60)}m ago`
  if (s < 86400) return `${Math.round(s / 3600)}h ago`
  return `${Math.round(s / 86400)}d ago`
}
