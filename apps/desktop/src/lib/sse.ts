/** One server-sent event. */
export interface SseEvent {
  event: string;
  data: string;
  id?: string;
}

/**
 * Incremental parser of a text/event-stream (WHATWG). EventSource cannot send an Authorization
 * header, so the app reads the stream with fetch and parses it here.
 */
export class SseParser {
  private buffer = '';
  private event = 'message';
  private data: string[] = [];
  private id: string | undefined;

  push(chunk: string): SseEvent[] {
    this.buffer += chunk;
    const out: SseEvent[] = [];
    let newline = this.buffer.search(/\r\n|\r|\n/);
    while (newline >= 0) {
      const line = this.buffer.slice(0, newline);
      const width = this.buffer.startsWith('\r\n', newline) ? 2 : 1;
      this.buffer = this.buffer.slice(newline + width);
      if (line === '') {
        if (this.data.length)
          out.push({ event: this.event, data: this.data.join('\n'), ...(this.id ? { id: this.id } : {}) });
        this.event = 'message';
        this.data = [];
      } else if (!line.startsWith(':')) {
        const colon = line.indexOf(':');
        const field = colon < 0 ? line : line.slice(0, colon);
        const value = colon < 0 ? '' : line.slice(colon + 1).replace(/^ /, '');
        if (field === 'event') this.event = value;
        else if (field === 'data') this.data.push(value);
        else if (field === 'id') this.id = value;
      }
      newline = this.buffer.search(/\r\n|\r|\n/);
    }
    return out;
  }
}
