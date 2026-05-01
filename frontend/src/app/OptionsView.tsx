import type { FormEvent } from "react";
import type { Config } from "../types";

type OptionsViewProps = {
  config: Config;
  setConfig: (updater: (prev: Config) => Config) => void;
  onSaveConfig: (event: FormEvent<HTMLFormElement>) => void;
};

function listToLines(values: string[]): string {
  return values.join("\n");
}

function linesToList(value: string): string[] {
  return value
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
}

export function OptionsView({ config, setConfig, onSaveConfig }: OptionsViewProps) {
  return (
    <>
      <h1 className="page-title">Options</h1>
      <div className="sysinfo-box" style={{ maxWidth: 480 }}>
        <div className="sysinfo-title">Configuration</div>
        <form className="options-form" onSubmit={onSaveConfig}>
          <div className="form-field">
            <label htmlFor="maxPackets">Max packets stored</label>
            <input
              id="maxPackets"
              type="number"
              min={100}
              max={50000}
              value={config.maxPackets}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, maxPackets: Number(e.target.value) }))
              }
            />
          </div>
          <div className="form-field">
            <label htmlFor="maxAlerts">Max alerts stored</label>
            <input
              id="maxAlerts"
              type="number"
              min={50}
              max={5000}
              value={config.maxAlerts}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, maxAlerts: Number(e.target.value) }))
              }
            />
          </div>
          <div className="form-field">
            <label htmlFor="packetSaveCount">Packet save count</label>
            <input
              id="packetSaveCount"
              type="number"
              min={1}
              max={10000}
              value={config.packetSaveCount}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, packetSaveCount: Number(e.target.value) }))
              }
            />
          </div>

          <div className="form-field checkbox-field">
            <label htmlFor="payloadFilteringEnabled">Payload filtering</label>
            <div className="checkbox-row">
              <input
                id="payloadFilteringEnabled"
                type="checkbox"
                checked={config.payloadFilteringEnabled}
                onChange={(e) =>
                  setConfig((prev) => ({ ...prev, payloadFilteringEnabled: e.target.checked }))
                }
              />
              <span>Enable payload security filtering rules</span>
            </div>
          </div>

          <div className="form-field">
            <label htmlFor="payloadPreviewLength">Payload preview length</label>
            <input
              id="payloadPreviewLength"
              type="number"
              min={50}
              max={2000}
              value={config.payloadPreviewLength}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, payloadPreviewLength: Number(e.target.value) }))
              }
            />
          </div>

          <div className="form-field">
            <label htmlFor="blockedPayloadKeywords">Blocked payload keywords (one per line)</label>
            <textarea
              id="blockedPayloadKeywords"
              rows={5}
              value={listToLines(config.blockedPayloadKeywords)}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, blockedPayloadKeywords: linesToList(e.target.value) }))
              }
            />
            <p className="field-help">
              Example: <code>password=</code>, <code>authorization:</code>, <code>token=</code>
            </p>
          </div>

          <div className="form-field">
            <label htmlFor="blockedPayloadPatterns">Blocked regex patterns (one per line)</label>
            <textarea
              id="blockedPayloadPatterns"
              rows={5}
              value={listToLines(config.blockedPayloadPatterns)}
              onChange={(e) =>
                setConfig((prev) => ({ ...prev, blockedPayloadPatterns: linesToList(e.target.value) }))
              }
            />
            <p className="field-help">
              Invalid regex entries are ignored by backend analyzers.
            </p>
          </div>

          <button type="submit" className="save-btn">
            Save Settings
          </button>
        </form>
      </div>
    </>
  );
}
