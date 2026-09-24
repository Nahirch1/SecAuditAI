import { useState, type FormEvent } from "react";
import { analyzeText, analyzeFile, ApiError, type AnalysisResponse } from "../api/client";

interface AnalyzerProps {
  token: string;
  onLogout: () => void;
}

const SEVERITY_COLORS: Record<string, string> = {
  Baja: "#4caf50",
  Media: "#ff9800",
  Alta: "#f44336",
  Crítica: "#b71c1c",
  Desconocida: "#9e9e9e",
};

export default function Analyzer({ token, onLogout }: AnalyzerProps) {
  const [mode, setMode] = useState<"text" | "file">("text");
  const [content, setContent] = useState("");
  const [file, setFile] = useState<File | null>(null);
  const [result, setResult] = useState<AnalysisResponse | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(false);

  async function handleSubmit(e: FormEvent) {
    e.preventDefault();
    setError(null);
    setResult(null);
    setLoading(true);

    try {
      const response =
        mode === "text"
          ? await analyzeText(token, content)
          : await analyzeFile(token, file as File);
      setResult(response);
    } catch (err) {
      if (err instanceof ApiError) {
        if (err.status === 401) {
          onLogout();
          return;
        }
        if (err.status === 429) {
          setError("Alcanzaste el límite de análisis por minuto. Esperá un momento e intentá de nuevo.");
        } else {
          setError(err.message);
        }
      } else {
        setError("No se pudo conectar con la API.");
      }
    } finally {
      setLoading(false);
    }
  }

  const canSubmit = mode === "text" ? content.trim().length > 0 : file !== null;

  return (
    <div className="analyzer-container">
      <header className="analyzer-header">
        <h1>SecAuditorIA</h1>
        <button onClick={onLogout} className="logout-button">
          Cerrar sesión
        </button>
      </header>

      <div className="mode-toggle">
        <button
          className={mode === "text" ? "active" : ""}
          onClick={() => setMode("text")}
          type="button"
        >
          Analizar texto
        </button>
        <button
          className={mode === "file" ? "active" : ""}
          onClick={() => setMode("file")}
          type="button"
        >
          Analizar archivo
        </button>
      </div>

      <form onSubmit={handleSubmit} className="analyzer-form">
        {mode === "text" ? (
          <textarea
            value={content}
            onChange={(e) => setContent(e.target.value)}
            placeholder="Pegá acá el log, configuración o código a auditar..."
            rows={8}
          />
        ) : (
          <input
            type="file"
            accept=".txt,.log,.json,.conf,.yaml,.yml"
            onChange={(e) => setFile(e.target.files?.[0] ?? null)}
          />
        )}

        {error && <p className="error-message">{error}</p>}

        <button type="submit" disabled={!canSubmit || loading}>
          {loading ? "Analizando..." : "Analizar"}
        </button>
      </form>

      {result && (
        <div className="result-card">
          <div className="result-header">
            <span
              className="severity-badge"
              style={{ backgroundColor: SEVERITY_COLORS[result.severity] ?? "#9e9e9e" }}
            >
              {result.severity}
            </span>
            <span className="report-id">Reporte #{result.reportId}</span>
          </div>
          <pre className="result-body">{result.result}</pre>
        </div>
      )}
    </div>
  );
}
