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