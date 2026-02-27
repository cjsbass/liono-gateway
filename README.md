# LIONO Gateway

The open-source AI assistant gateway server that powers [LIONO](https://lionoai.com).

LIONO Gateway is a WebSocket-based server that connects AI models to your tools — email, calendar, web search, task management, and more. It runs on your own dedicated server, keeping all your data private.

## Features

- **Private by design** — runs on your own server, no shared infrastructure
- **Google integration** — Gmail, Calendar, Contacts, Drive, and more
- **AI-powered tools** — web search, weather, system monitoring, code assistance
- **Multi-agent support** — spawn sub-agents for complex tasks
- **Automation** — cron jobs, reminders, and scheduled tasks
- **Real-time** — WebSocket protocol for instant communication

## How It Works

LIONO Gateway acts as a bridge between the LIONO mobile app and AI models (via OpenRouter). When you send a message, the gateway:

1. Receives the message via WebSocket
2. Sends it to an AI model with available tool definitions
3. Executes tool calls (search, email, calendar, etc.) on your behalf
4. Streams the response back to the app

All processing happens on your server. LIONO's backend only stores your account info and health metrics — never your conversations or personal data.

## Verification

You can verify the code running on your server matches this repository:

```bash
# Check the source
cat /opt/openclaw/gateway-server.js

# Compare SHA-256 hash
sha256sum /opt/openclaw/gateway-server.js
```

Compare with the hash published in [Releases](https://github.com/cjsbass/lionoai/releases).

## License

Published under the [OCVSAL (Open Core Ventures Source Available License)](https://github.com/OpenCoreVentures/open-core-ventures-source-available-license).

## Links

- [LIONO App](https://lionoai.com)
- [Privacy Policy](https://lionoai.com/privacy)
- [Terms of Service](https://lionoai.com/terms)
- [Trust & Transparency](https://lionoai.com/trust)
