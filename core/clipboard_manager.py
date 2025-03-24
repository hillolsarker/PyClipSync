import pyperclip

class ClipboardManager:
    def __init__(self):
        """
        Initializes the ClipboardManager instance.

        Attributes:
            last_content (str): Stores the last content of the clipboard.
        """
        self.last_content: str = ""

    def get_clipboard(self) -> str:
        """
        Retrieves the current text content from the system clipboard.

        Returns:
            str: The text content currently stored in the clipboard.
        """
        return pyperclip.paste()

    def has_changed(self) -> bool:
        """
        Checks if the clipboard content has changed since the last check.

        Returns:
            bool: True if the clipboard content has changed, False otherwise.
        """
        current = self.get_clipboard()
        if current != self.last_content:
            self.last_content = current
            return True
        return False

    def copy_to_clipboard(self, content: str) -> None:
        """
        Copies the given content to the system clipboard.

        Args:
            content (str): The text content to be copied to the clipboard.

        Returns:
            None
        """
        pyperclip.copy(content)
        