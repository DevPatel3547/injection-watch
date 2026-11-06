"""Local fake servers that speak real wire formats (Anthropic Messages API, OpenAI chat completions).

They answer with a tiny keyword "model" so results are deterministic. They are test doubles, not models:
anything produced against them is labelled as fake-server output.
"""
