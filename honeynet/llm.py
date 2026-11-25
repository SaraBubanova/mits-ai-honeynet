"""The only file that talks to the model.

Plan: any OpenAI-compatible API. Settings come from .env:
    LLM_BASE_URL, LLM_API_KEY, LLM_MODEL  (plus LLM_MODEL_<STEP> to override per step)

TODO: chat_json(step, system, user, schema) with retries and a disk cache,
and run_agent(step, system, user, tools) for the tool-using loop.
"""
