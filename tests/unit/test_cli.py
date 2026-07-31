from landmine.cli import build_parser


def test_help_lists_four_commands() -> None:
    help_text = build_parser().format_help()
    for command in ("why", "assumptions", "blast", "defuse"):
        assert command in help_text
