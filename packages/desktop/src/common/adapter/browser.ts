/**
 * @license
 * Copyright 2025 AionUi (aionui.com)
 * SPDX-License-Identifier: Apache-2.0
 */

import { bridge } from '@/common/platform/bridge';
import type { ElectronBridgeAPI } from '@/common/types/platform/electron';

interface CustomWindow extends Window {
  electronAPI?: ElectronBridgeAPI;
  __websocketReconnect?: () => void;
}

const win = window as CustomWindow;

/**
 * 适配electron的API到浏览器中,建立renderer和main的通信桥梁, 与preload.ts中的注入对应
 * */
if (win.electronAPI) {
  // Electron 环境 - 使用 IPC 通信
  bridge.adapter({
    emit(name, data) {
      return win.electronAPI.emit(name, data);
    },
    on(emitter) {
      win.electronAPI?.on((event) => {
        try {
          const { value } = event;
          const { name, data } = JSON.parse(value);
          emitter.emit(name, data);
        } catch (e) {
          console.warn('JSON parsing error:', e);
        }
      });
    },
  });
} else {

  // Web runtime: the platform bridge (Electron IPC) has no server-side
  // counterpart. Every outbound frame (subscribe-*, write-renderer-log, ...)
  // is rejected with REALTIME_UNSUPPORTED_MESSAGE and subscribe callbacks
  // never return; the realtime data path is the httpBridge WS singleton
  // (message.stream, runtime events, fs monitor). A dedicated bridge socket
  // would only consume one of Safari's ~6 per-host HTTP/1.1 pool slots — on
  // unstable mobile links that slot is the difference between a message POST
  // being sent vs queued until timeout. Keep the bridge transport a no-op in
  // web mode.
  bridge.adapter({
    emit() {},
    on() {},
  });

  // The login flow (AuthContext) calls this after login to re-establish the
  // bridge socket with the fresh session cookie. With no bridge socket there
  // is nothing to reconnect — the httpBridge realtime singleton reconnects
  // itself on close, so expose a safe no-op.
  win.__websocketReconnect = () => {};
}
