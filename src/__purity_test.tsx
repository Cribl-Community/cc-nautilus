import { useState, useEffect } from 'react';

function useNow(intervalMs = 60000): number {
  const [now, setNow] = useState(() => Date.now());
  useEffect(() => {
    const id = setInterval(() => setNow(Date.now()), intervalMs);
    return () => clearInterval(id);
  }, [intervalMs]);
  return now;
}

export function Badge({ ts }: { ts: number }) {
  const now = useNow();
  const age = now - ts;
  return <span>{age}</span>;
}
