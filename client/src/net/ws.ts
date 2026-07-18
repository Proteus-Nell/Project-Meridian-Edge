// WebSocket delivery client (CLAUDE.md §3). Auth is the first frame after
// connect; the server answers with a rotated session token (§2.3) and then
// pushes queued + live envelopes. Acks go back over the socket.

import { fromBase64 } from "../util/base64";

export interface WsHandlers {
  onToken(token: string): void;
  onEnvelope(id: number, envelope: Uint8Array): void;
  onClose(intentional: boolean): void;
}

// Server closes an idle connection (no frames at all) after 90s (§5, §7.11
// WS_IDLE_TIMEOUT_SECONDS); ping well inside that window so a healthy,
// otherwise-quiet connection is never mistaken for an idle one.
const HEARTBEAT_INTERVAL_MS = 30_000;

export class WsClient {
  private socket: WebSocket | null = null;
  private closing = false;
  private heartbeat: ReturnType<typeof setInterval> | null = null;

  isConnected(): boolean {
    return this.socket !== null && this.socket.readyState === WebSocket.OPEN;
  }

  connect(token: string, handlers: WsHandlers): void {
    this.close();
    this.closing = false;
    const scheme = location.protocol === "https:" ? "wss" : "ws";
    const socket = new WebSocket(`${scheme}://${location.host}/v1/ws`);
    this.socket = socket;
    socket.onopen = () => {
      socket.send(JSON.stringify({ type: "auth", token }));
      this.heartbeat = setInterval(() => {
        if (this.isConnected()) {
          this.socket?.send(JSON.stringify({ type: "ping" }));
        }
      }, HEARTBEAT_INTERVAL_MS);
    };
    socket.onmessage = (event: MessageEvent) => {
      if (typeof event.data !== "string") {
        return;
      }
      let frame: unknown;
      try {
        frame = JSON.parse(event.data);
      } catch {
        return;
      }
      if (typeof frame !== "object" || frame === null) {
        return;
      }
      const typed = frame as { type?: unknown; token?: unknown; id?: unknown; envelope?: unknown };
      if (typed.type === "token" && typeof typed.token === "string") {
        handlers.onToken(typed.token);
        return;
      }
      if (
        typed.type === "message" &&
        typeof typed.id === "number" &&
        typeof typed.envelope === "string"
      ) {
        let envelope: Uint8Array;
        try {
          envelope = fromBase64(typed.envelope);
        } catch {
          return;
        }
        handlers.onEnvelope(typed.id, envelope);
      }
    };
    socket.onclose = () => {
      const intentional = this.closing;
      this.stopHeartbeat();
      this.socket = null;
      handlers.onClose(intentional);
    };
  }

  ack(ids: readonly number[]): void {
    if (this.isConnected()) {
      this.socket?.send(JSON.stringify({ type: "ack", ids }));
    }
  }

  private stopHeartbeat(): void {
    if (this.heartbeat !== null) {
      clearInterval(this.heartbeat);
      this.heartbeat = null;
    }
  }

  close(): void {
    if (this.socket !== null) {
      this.closing = true;
      this.stopHeartbeat();
      this.socket.close();
      this.socket = null;
    }
  }
}
