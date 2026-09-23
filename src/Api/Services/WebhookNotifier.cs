using System.Text;
using System.Text.Json;

namespace SecAuditAI.Api.Services;

public record CriticalAlertPayload(
    int ReportId,
    string Username,
    string SourceFileName,
    string Severity,
    string Summary,
    DateTime DetectedAt);

public class WebhookNotifier
{
    private readonly HttpClient _httpClient;
    private readonly IConfiguration _config;
    private readonly ILogger<WebhookNotifier> _logger;

    public WebhookNotifier(HttpClient httpClient, IConfiguration config, ILogger<WebhookNotifier> logger)
    {
        _httpClient = httpClient;
        _config = config;
        _logger = logger;
    }

    public async Task NotifyCriticalFindingAsync(CriticalAlertPayload payload)
    {
        var webhookUrl = _config["N8n:WebhookUrl"];

        if (string.IsNullOrWhiteSpace(webhookUrl))
        {
            _logger.LogWarning("N8n:WebhookUrl no está configurado. Se omite la notificación.");
            return;
        }

        try
        {
            var json = JsonSerializer.Serialize(payload);
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            var response = await _httpClient.PostAsync(webhookUrl, content);

            if (response.IsSuccessStatusCode)
            {
                _logger.LogInformation("Alerta crítica enviada a n8n para el reporte #{ReportId}.", payload.ReportId);
            }
            else
            {
                _logger.LogWarning("n8n respondió con código {StatusCode} al notificar el reporte #{ReportId}.",
                    response.StatusCode, payload.ReportId);
            }
        }
        catch (Exception ex)
        {
            // El webhook es "best effort": si n8n está caído o inaccesible,
            // no queremos que falle el análisis de seguridad por eso.
            _logger.LogError(ex, "Error al notificar a n8n para el reporte #{ReportId}.", payload.ReportId);
        }
    }
}
