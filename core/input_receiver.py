import socket
import threading
import struct
import json
from pynput.mouse import Controller as MouseController
from pynput.keyboard import Controller as KeyboardController

class InputReceiver:
    def __init__(self, config):
        self.mouse = MouseController()
        self.keyboard = KeyboardController()
        self.config = config

    def start(self):
        threading.Thread(target=self._input_server_loop, daemon=True).start()

    def _input_server_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind(("", self.config.input_port))
        sock.listen(5)
        while True:
            conn, _ = sock.accept()
            length_data = conn.recv(4)
            if not length_data:
                conn.close()
                continue
            msg_len = struct.unpack("!I", length_data)[0]
            data = b''
            while len(data) < msg_len:
                chunk = conn.recv(msg_len - len(data))
                if not chunk:
                    break
                data += chunk
            conn.close()
            try:
                event = json.loads(data.decode())
                if event["type"] == "mouse":
                    res = self.get_screen_resolution()
                    abs_x = int(event["x"] * res[0])
                    abs_y = int(event["y"] * res[1])
                    self.mouse.position = (abs_x, abs_y)
                elif event["type"] == "keyboard":
                    self.keyboard.type(event["key"])
            except Exception as e:
                print(f"Input parsing error: {e}")

    def get_screen_resolution(self):
        from screeninfo import get_monitors
        monitors = get_monitors()
        if monitors:
            return (monitors[0].width, monitors[0].height)
        return (1920, 1080)