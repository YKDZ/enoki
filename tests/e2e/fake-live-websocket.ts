import type { Page } from "@playwright/test";

type FakeLiveWebSocketOptions = {
  deferOpenFromGeneration?: number;
};

declare global {
  interface Window {
    __enokiLiveSocket?: {
      close: () => void;
      emit: (message: unknown) => void;
      open: () => void;
    };
    __enokiLiveSocketGeneration?: number;
    __enokiLiveSocketOpenGeneration?: number;
  }
}

export async function installFakeLiveWebSocket(
  page: Page,
  options: FakeLiveWebSocketOptions = {},
) {
  await page.addInitScript((fakeOptions: FakeLiveWebSocketOptions) => {
    class FakeWebSocket extends EventTarget {
      static readonly CLOSED = 3;
      static readonly CONNECTING = 0;
      static readonly OPEN = 1;

      readyState = FakeWebSocket.CONNECTING;

      constructor() {
        super();
        const socket = this as typeof this & { generation: number };
        window.__enokiLiveSocket = this;
        socket.generation = (window.__enokiLiveSocketGeneration ?? 0) + 1;
        window.__enokiLiveSocketGeneration = socket.generation;
        if (fakeOptions.deferOpenFromGeneration !== socket.generation) {
          setTimeout(() => this.open(), 0);
        }
      }

      open() {
        if (this.readyState !== FakeWebSocket.CONNECTING) {
          return;
        }

        this.readyState = FakeWebSocket.OPEN;
        window.__enokiLiveSocketOpenGeneration = (
          this as typeof this & { generation: number }
        ).generation;
        this.dispatchEvent(new Event("open"));
      }

      close() {
        if (this.readyState === FakeWebSocket.CLOSED) {
          return;
        }

        this.readyState = FakeWebSocket.CLOSED;
        this.dispatchEvent(new Event("close"));
      }

      emit(message: unknown) {
        this.dispatchEvent(
          new MessageEvent("message", {
            data: JSON.stringify(message),
          }),
        );
      }

      send() {}
    }

    window.WebSocket = FakeWebSocket as unknown as typeof WebSocket;
  }, options);
}

export async function closeFakeLiveWebSocket(page: Page) {
  await page.evaluate(() => window.__enokiLiveSocket?.close());
}

export async function emitFakeLiveWebSocketMessage(
  page: Page,
  message: unknown,
) {
  await page.evaluate((liveMessage) => {
    window.__enokiLiveSocket?.emit(liveMessage);
  }, message);
}

export async function fakeLiveSocketGeneration(page: Page) {
  return page.evaluate(() => window.__enokiLiveSocketGeneration ?? 0);
}

export async function fakeLiveSocketOpenGeneration(page: Page) {
  return page.evaluate(() => window.__enokiLiveSocketOpenGeneration ?? 0);
}

export async function openFakeLiveWebSocket(page: Page) {
  await page.evaluate(() => window.__enokiLiveSocket?.open());
}
