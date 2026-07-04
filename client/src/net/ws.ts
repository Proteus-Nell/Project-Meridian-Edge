// WebSocket delivery client (CLAUDE.md §3). Auth is the first frame after
// connect; the server answers with a rotated session token (§2.3) and then
// pushes queued + live envelopes. Acks go back over the socket.

import { fromBase64 } from "../util/base64";

export interface WsHandlers {
  onToken(token: string): void;
  onEnvelope(id: number, envelope: Uint8Array): void;
  onClose(intentional: boolean): void;
}

export class WsClient {
  private socket: WebSocket | null = null;
  private closing = false;

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
      this.socket = null;
      handlers.onClose(intentional);
    };
  }

  ack(ids: readonly number[]): void {
    if (this.isConnected()) {
      this.socket?.send(JSON.stringify({ type: "ack", ids }));
    }
  }

  close(): void {
    if (this.socket !== null) {
      this.closing = true;
      this.socket.close();
      this.socket = null;
    }
  }
}
