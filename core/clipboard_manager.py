import pyperclip

class ClipboardManager:
    def __init__(self):
        self.last_content: str = ""

    def get_clipboard(self) -> str:
        return pyperclip.paste()

    def has_changed(self) -> bool:
        current = self.get_clipboard()
        if current != self.last_content:
            self.last_content = current
            return True
        return False

    def copy_to_clipboard(self, content: str) -> None:
        pyperclip.copy(content)
        