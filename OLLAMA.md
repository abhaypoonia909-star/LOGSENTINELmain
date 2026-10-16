# Local SentinelAI (Ollama)

LogSentinel chat uses a language model that runs on your machine through
[Ollama](https://ollama.com). This is genuine local inference, not a
rule-based or TF-IDF reply.

A paid API, cloud AI provider, and API key are **not** required for normal
chat. The official OpenAI SDK is not a runtime dependency. After the model
is downloaded once, inference works offline. Log excerpts are sent only to
the local Ollama process. They are not sent to an external service, and the
assistant does not fall back to OpenAI.

## Windows laptop (8 GB RAM)

Use the small default model. Do **not** pull a 7B/8B or larger model on an
8 GB machine; it will swap or fail to load.

Recommended default:

```text
llama3.2:1b
```

Compatible small alternatives if you already have one installed:

```text
qwen2.5:0.5b
qwen2.5:1.5b
gemma2:2b
```

Set `OLLAMA_MODEL` to the exact name you pulled. LogSentinel does not
download or load a model automatically.

## One-time setup

1. Install Ollama for Windows from https://ollama.com/download
2. Start Ollama. It should listen on `http://127.0.0.1:11434`
3. Download the small model once (needs internet only for this step):

```powershell
ollama pull llama3.2:1b
```

4. Confirm the model is listed:

```powershell
ollama list
```

5. Copy `.env.example` to `.env` (project root and/or `backend/.env`).
   `config.py` loads the project-root file first, then `backend/.env` with
   `override=True` (backend wins). Keep:

```text
AI_PROVIDER=ollama
OLLAMA_BASE_URL=http://127.0.0.1:11434
OLLAMA_MODEL=llama3.2:1b
OLLAMA_TIMEOUT_SECONDS=60
OLLAMA_TEMPERATURE=0.3
OLLAMA_NUM_CTX=1024
OLLAMA_NUM_PREDICT=80
OLLAMA_KEEP_ALIVE=60m
```

   Those numbers are the **code defaults** from `backend/utils/ollama_settings.py`
   when the variables are unset. `AIService` is the live reader. `Config.OLLAMA_*`
   stores the same names for documentation; chat still applies compact
   `num_ctx` caps (768 general / 1024 analysis) after reading the defaults.

6. Start the Flask server from `backend`:

```powershell
cd backend
python app.py
```

7. Sign in on the LogSentinel page and open the AI assistant.

### Automatic start on Windows (development)

`python app.py` now checks `http://127.0.0.1:11434/api/tags` in the background.
If Ollama is not answering it starts the **already installed** `ollama.exe`
(`ollama serve`, default loopback binding, no console window), waits up to
`OLLAMA_AUTOSTART_WAIT_SECONDS` (default 45; a cold start takes about 25–30 s) for the API, then confirms
`llama3.2:1b` is installed. Console lines are prefixed `[LogSentinel][Ollama]`.

It never runs `ollama pull`, never changes `OLLAMA_HOST`, and refuses to start
Ollama if `OLLAMA_HOST` points at a non-loopback address. It is skipped under
gunicorn/Render, when `OLLAMA_BASE_URL` is not loopback, when
`AI_PROVIDER=openai`, or when `OLLAMA_AUTOSTART=0`. If the model is missing it
prints the exact `ollama pull llama3.2:1b` command for you to run.

### Using the laptop's Ollama from the Render website

Render cannot reach `127.0.0.1:11434` (that address is Render's own container),
and Ollama has no authentication, so it is never exposed directly. Instead:

```
Browser -> Flask on Render (JWT) -> https://<ngrok domain> + Bearer token
       -> laptop: ngrok -> tools/ollama_gateway.py (127.0.0.1:11435) -> Ollama 127.0.0.1:11434
```

One command on the laptop (keep the window open while you want chat to work):

```cmd
backend\tools\connect_ollama.cmd
```

First run: it offers to download the portable ngrok zip (official URL, no
installer), asks for your free ngrok authtoken and free static domain, creates
the gateway token in `%LOCALAPPDATA%\LogSentinel\` (outside the repo) and prints
it once. It then self-tests the public URL (no token -> 401, token -> model list)
and prints the two Render variables: `OLLAMA_BASE_URL=https://<domain>` and
`OLLAMA_AUTH_TOKEN=<token>`. The gateway forwards only `GET /api/tags` and
`POST /api/chat`, caps bodies at 1 MB and rate-limits; `/api/pull`, `/api/delete`
etc. are blocked. `--show-token` prints the token again.

## Offline operation

After the model is on disk:

- Ollama can answer without internet
- Flask can answer without internet
- Detection, Attack Summary, PDF reports, Live Alerts, Incident
  Investigation, and source-code scanning keep working without the model

If Ollama is stopped or the model is missing, chat returns a configuration
error that tells you how to start Ollama and run `ollama pull`. It does not
invent findings or switch to a cloud model.

## Environment variables

| Variable | Required | Default | Notes |
|---|---|---|---|
| `AI_PROVIDER` | No | `ollama` | `ollama`, `local`, and `auto` all use local Ollama. There is no cloud fallback. `openai` is opt-in only. |
| `OLLAMA_BASE_URL` | No | `http://127.0.0.1:11434` | Local Ollama URL. Do not point this at a public host if you want logs to stay on the laptop. |
| `OLLAMA_MODEL` | No | `llama3.2:1b` | Must match a model already installed with `ollama pull`. |
| `OLLAMA_TIMEOUT_SECONDS` | No | `60` | Used by `AIService` / `ollama_runtime_settings()`. First reply can be slower while the small model loads. |
| `OLLAMA_TEMPERATURE` | No | `0.3` | Lower values stay more factual. |
| `OLLAMA_NUM_CTX` | No | `1024` | Then capped to 768 (general) or 1024 (analysis) in `_request_options`. |
| `OLLAMA_NUM_PREDICT` | No | `80` | General questions. Short/social uses 48; analysis 120; long-answer 512. |
| `OLLAMA_KEEP_ALIVE` | No | `60m` | How long Ollama keeps the model loaded after a reply. |
| `OLLAMA_HISTORY_TURNS` | No | `6` | Recent chat turns sent with the next question. |
| `OLLAMA_AUTOSTART` | No | `1` | Dev only (`python app.py`). `0` disables starting the installed Ollama automatically. |
| `OLLAMA_AUTH_TOKEN` | Only with a remote `OLLAMA_BASE_URL` | empty | Bearer token for `backend/tools/ollama_gateway.py`. Required (with `https://`) whenever `OLLAMA_BASE_URL` is not loopback. |
| `OLLAMA_AUTOSTART_WAIT_SECONDS` | No | `45` | How long the dev bootstrap waits for `/api/tags` after starting Ollama (1–120). |
| `OPENAI_API_KEY` | Only if `AI_PROVIDER=openai` | empty | Not used by the default local assistant. |

No Ollama API key is required.

## What the assistant can and cannot do

It can:

- Answer general questions and explain programming or cybersecurity topics
- Use recent messages in the current chat for follow-up questions
- Reply in English, Hindi, or Roman-script Hinglish matching the latest message
- Handle short greetings such as hey, hlo, and thanks without a robotic translation
- Explain stored LogSentinel findings, attack types, attempt counts, IPs,
  severity, original log evidence, and incident details when an owned
  `analysis_id` is attached

It cannot:

- Match ChatGPT quality. `llama3.2:1b` is a small local model chosen for 8 GB RAM.
- Invent IP addresses, timestamps, scan results, or attack confirmations
- Treat AI text as new evidence. Confirmed detections are detector rule matches.
  Incident groupings are investigative hypotheses.
- Download or switch models by itself

## Launch and try a conversation

1. Start Ollama, then confirm `ollama list` shows `llama3.2:1b`.
2. From `backend`, run `python app.py`.
3. Sign in, open SentinelAI, and ask a general question such as
   "What is a Python list?"
4. After an analysis, ask "Summarize the detected attacks and their source IPs."
5. Keep Ollama on `127.0.0.1:11434`. Prompts stay on this machine.

## Tests (no model download)

Most `test_ai` cases mock the Ollama client. Run that suite **alone**:

```powershell
cd backend
python -m unittest test_ai -v
```

`test_real_ollama_latency_when_available` **does** call local Ollama when the
server and `llama3.2:1b` are reachable. It is skipped or still runs a live
check depending on that availability. Do not treat the older sentence
“those tests never call a real model” as current.

## Optional live check

Only after Ollama is running and `llama3.2:1b` is installed:

```powershell
ollama list
curl http://127.0.0.1:11434/api/tags
```

Then send a signed-in chat message from the UI, POST `/api/ai` with a JWT, or use `/api/ai/stream` for token-by-token replies.
Until that live check succeeds, treat local inference as not yet verified on
this machine.
