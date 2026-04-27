# Advanced Packet Scanner

This repository now includes a C# API backend and a React + TypeScript frontend.

## Architecture

- Network packet capture and protocol analysis remain in C#.
- A new ASP.NET Core API exposes capture state, packet data, alerts, and config.
- A React + TypeScript frontend consumes the API and provides the UI.

## Projects

- `NetworkMonitor` (existing): WinForms desktop app (legacy UI path).
- `NetworkMonitor.Api` (new): ASP.NET Core backend API.
- `frontend` (new): Vite + React + TypeScript web frontend.

## Requirements

- .NET SDK 10.0+
- Node.js 20+
- Npcap installed (WinPcap compatibility mode recommended)
- Run the API process as Administrator for packet capture access

## Run the API

From repository root:

```powershell
dotnet run --project NetworkMonitor.Api/NetworkMonitor.Api.csproj
```

Default API URL is typically:

- `https://localhost:7069`
- `http://localhost:5069`

## Run the Frontend

From repository root:

```powershell
cd frontend
npm install
npm run dev
```

Open:

- `http://localhost:5173`

If your API URL differs (or you do not use the default Vite proxy), set an environment variable before running the frontend:

```powershell
$env:VITE_API_BASE_URL="https://localhost:7069"
npm run dev
```

Or copy values from `frontend/.env.example` into a local `.env` file in `frontend/`.

## API Endpoints

- `GET /api/dashboard`
- `GET /api/devices`
- `POST /api/capture/start` with body `{ "deviceIndex": 0 }`
- `POST /api/capture/pause`
- `POST /api/capture/resume`
- `GET /api/alerts`
- `DELETE /api/alerts`
- `GET /api/config`
- `PUT /api/config`

## Notes

- The API reuses backend logic from `Backend/` and `Backend/ProtocolAnalyzers/`.
- Legacy WinForms files were kept so you can compare behavior while moving fully to web UI.
- You may see existing SSL/TLS analyzer warnings from older cryptography APIs; these are warnings, not API migration errors.
