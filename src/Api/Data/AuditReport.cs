namespace SecAuditAI.Api.Data;

public class AuditReport
{
    public int Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string SourceFileName { get; set; } = string.Empty; // "texto-directo" si no vino de archivo
    public string AnalyzedContent { get; set; } = string.Empty;
    public string Result { get; set; } = string.Empty;
    public string Severity { get; set; } = "Desconocida"; // Baja/Media/Alta/Crítica, extraída del resultado
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
