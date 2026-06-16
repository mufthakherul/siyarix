import io
from typing import Any, Callable

from rich.console import Console
from prompt_toolkit.application import Application
from prompt_toolkit.layout.containers import HSplit, Window
from prompt_toolkit.layout.controls import FormattedTextControl, BufferControl
from prompt_toolkit.layout.layout import Layout
from prompt_toolkit.buffer import Buffer
from prompt_toolkit.formatted_text import ANSI, HTML
from prompt_toolkit.key_binding import KeyBindings

class FullScreenAdapter:
    """Adapts Siyarix to use a full-screen prompt_toolkit layout while capturing Rich output."""

    def __init__(self, get_header_html: Callable[[], HTML], get_footer_html: Callable[[], HTML]):
        self._history_ansi = ""
        self._output_buffer = io.StringIO()
        self.console = Console(file=self._output_buffer, force_terminal=True, color_system="truecolor", width=120)
        self.get_header_html = get_header_html
        self.get_footer_html = get_footer_html

        self.history_buffer = Buffer(read_only=True)
        self.prompt_buffer = Buffer(multiline=False)

        self.app: Application | None = None
        self._setup_layout()

    def _setup_layout(self) -> None:
        top_bar = Window(
            FormattedTextControl(self.get_header_html),
            height=5,
            dont_extend_height=True
        )

        self.history_window = Window(
            FormattedTextControl(lambda: ANSI(self._history_ansi)),
            wrap_lines=True,
            always_hide_cursor=True
        )

        prompt_window = Window(
            BufferControl(buffer=self.prompt_buffer),
            height=1,
            dont_extend_height=True
        )

        bottom_bar = Window(
            FormattedTextControl(self.get_footer_html),
            height=1,
            dont_extend_height=True
        )

        kb = KeyBindings()

        @kb.add("c-c")
        def _(event: Any) -> None:
            event.app.exit(exception=KeyboardInterrupt())

        @kb.add("c-d")
        def _(event: Any) -> None:
            event.app.exit(exception=EOFError())

        @kb.add("enter")
        def _(event: Any) -> None:
            text = self.prompt_buffer.text
            self.prompt_buffer.text = ""
            event.app.exit(result=text)

        self.app = Application(
            layout=Layout(HSplit([top_bar, self.history_window, prompt_window, bottom_bar])),
            key_bindings=kb,
            full_screen=True,
            mouse_support=True
        )

    def print(self, *args: Any, **kwargs: Any) -> None:
        """Capture Rich print and update UI."""
        self.console.print(*args, **kwargs)
        self._flush()

    def _flush(self) -> None:
        text = self._output_buffer.getvalue()
        if text:
            self._history_ansi += text
            self._output_buffer.truncate(0)
            self._output_buffer.seek(0)
            if self.app and self.app.is_running:
                self.app.invalidate()

    async def prompt_async(self) -> str:
        """Prompt user for input asynchronously."""
        if not self.app:
            return ""
        return await self.app.run_async()
