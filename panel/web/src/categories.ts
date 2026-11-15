// The pisentry Top 10, as in the agent's internal/event catalog.
export const categories: { id: string; name: string }[] = [
  { id: 'PS01', name: 'SSH brute force' },
  { id: 'PS02', name: 'Suspicious login' },
  { id: 'PS03', name: 'Insecure posture' },
  { id: 'PS04', name: 'Privilege escalation' },
  { id: 'PS05', name: 'Persistence' },
  { id: 'PS06', name: 'Cryptominer' },
  { id: 'PS07', name: 'Unexpected listener' },
  { id: 'PS08', name: 'Reverse shell' },
  { id: 'PS09', name: 'Port scan' },
  { id: 'PS10', name: 'Critical file tampering' },
]

export function categoryName(id: string): string {
  if (id === 'PS00') return 'pisentry itself'
  return categories.find((c) => c.id === id)?.name ?? id
}

export const severities = ['info', 'low', 'medium', 'high', 'critical'] as const
