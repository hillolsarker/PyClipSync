import threading
import socket
import struct
import logging
from typing import List, Tuple
from pynput import mouse, keyboard
from screeninfo import get_monitors
import json

class InputManager:
    def __init__(self, config, peer_discovery, layout: List[str], name: str):
        self.config = config
        self.peer_discovery = peer_discovery
        self.layout = layout
        self.name = name
        self.current_index = layout.index(name)
        self.active_peer = name  # Start with local control
        self.own_width, self.own_height = self.get_screen_resolution()

    def get_screen_resolution(self) -> Tuple[int, int]:
        monitors = get_monitors()
        if monitors:
            return monitors[0].width, monitors[0].height
        return (1920, 1080)

    def start(self):
        threading.Thread(target=self._mouse_loop, daemon=True).start()
        threading.Thread(target=self._keyboard_loop, daemon=True).start()

    def _mouse_loop(self):
        def on_move(x, y):
            # LEFT EDGE → switch to left neighbor (in layout)
            if x <= 0 and self.current_index < len(self.layout) - 1:
                self._switch_to(self.layout[self.current_index + 1])
            # RIGHT EDGE → switch to right neighbor (in layout)
            elif x >= self.own_width * 0.95 and self.current_index > 0:
                self._switch_to(self.layout[self.current_index - 1])
            elif self.active_peer == self.name:
                self._send_mouse_event(x, y)

        mouse.Listener(on_move=on_move).start()

    def _keyboard_loop(self):
        def on_press(key):
            if self.active_peer != self.name:
                self._send_keyboard_event(str(key))
        keyboard.Listener(on_press=on_press).start()

    def _switch_to(self, peer_name: str):
        logging.info(f"Switching control to {peer_name}")
        self.active_peer = peer_name
        self.current_index = self.layout.index(peer_name)

    def _send_mouse_event(self, x, y):
        normalized_x = x / self.own_width
        normalized_y = y / self.own_height
        event = json.dumps({"type": "mouse", "x": normalized_x, "y": normalized_y})
        self._send_to_active_peer(event)

    def _send_keyboard_event(self, key):
        event = json.dumps({"type": "keyboard", "key": key})
        self._send_to_active_peer(event)

    def _send_to_active_peer(self, event_str: str):
        peers = self.peer_discovery.get_peers_snapshot()
        for ip, _ in peers.items():
            if self.peer_discovery.get_name_by_ip(ip) == self.active_peer:
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.connect((ip, self.config.input_port))
                    data = event_str.encode()
                    sock.sendall(struct.pack("!I", len(data)) + data)
                    sock.close()
                except Exception as e:
                    logging.warning(f"Failed to send input to {ip}: {e}")
                    