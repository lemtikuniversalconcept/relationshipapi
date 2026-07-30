import { GraphEvent } from './types';

type EventSink = (event: GraphEvent) => void;

const graphEventListeners = new Set<EventSink>();

export function registerGraphEventListener(listener: EventSink): () => void {
  graphEventListeners.add(listener);
  return () => {
    graphEventListeners.delete(listener);
  };
}

export function broadcastGraphEvent(event: GraphEvent): void {
  for (const listener of graphEventListeners) {
    try {
      listener(event);
    } catch {
      // Best effort fan-out.
    }
  }
}
