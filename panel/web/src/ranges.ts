// Time ranges the Overview and host pages can show. id is what the API takes as since.
export const ranges = [
  { id: '1h', label: '1h', hours: 1 },
  { id: '24h', label: '24h', hours: 24 },
  { id: '168h', label: '7d', hours: 168 },
  { id: '720h', label: '30d', hours: 720 },
] as const

export type Range = (typeof ranges)[number]

// The most events a page asks for to draw its chart.
export const EVENT_CAP = 1000
