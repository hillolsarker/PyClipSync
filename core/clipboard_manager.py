import pyperclip

class ClipboardManager:
    def __init__(self):
        self.last_content = ""

    def get_clipboard(self):
        return pyperclip.paste()

    def has_changed(self):
        current = self.get_clipboard()
        if current != self.last_content:
            self.last_content = current
            return True
        return False

    def copy_to_clipboard(self, content):
        pyperclip.copy(content)
        