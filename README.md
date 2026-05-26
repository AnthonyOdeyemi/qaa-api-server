# QAA AI Assessor Tool — API Server

Backend server for the AI-Assisted QAA Assessor Tool built for the TVET IDEAS World Bank project (NBTE/NSQ Nigeria).

## What this does
Acts as a secure middleware between the QAA frontend tool and the Anthropic Claude API. Handles all AI generation requests for:
- ARF01A Assessment Plan generation
- ARF02A Observation Report with NSQ PC mapping
- ARF01A Feedback Report (sandwich method)

## Tech stack
- Node.js + Express
- Anthropic Claude API (claude-sonnet-4-5)
- Deployed on Railway.app

## Environment variables
ANTHROPIC_API_KEY=your-key-here

## Endpoints
POST /api/claude - Send messages to Claude API
GET /health - Server health check

## Related
- Frontend: Deployed on Netlify
- NSQ data: Computer Hardware Maintenance & Repairs, Garment Making & Fashion Designing, Computer Networking, Aquaculture & Fishery, Automobile Engineering
