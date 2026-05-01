import type { FormEvent } from "react";
import type { Config } from "../types";

type OptionsViewProps = {
  config: Config;
  setConfig: (updater: (prev: Config) => Config) => void;
  onSaveConfig: (event: FormEvent<HTMLFormElement>) => void;
};

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
          <button type="submit" className="save-btn">
            Save Settings
          </button>
        </form>
      </div>
    </>
  );
}
