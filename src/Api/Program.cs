using Prometheus;
using Microsoft.EntityFrameworkCore;
using SecAuditAI.Api.Data;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.RateLimiting;
using Microsoft.IdentityModel.Tokens;
using Microsoft.SemanticKernel;
using System.Threading.RateLimiting;

var builder = WebApplication.CreateBuilder(args);

// ---------- Configuración JWT ----------
var jwtKey = builder.Configuration["Jwt:Key"]
    ?? throw new InvalidOperationException("Falta Jwt:Key en la configuración (user-secrets).");
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "SecAuditAI";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "SecAuditAI.Client";

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = jwtAudience,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey))
        };
    });

// ---------- Políticas de autorización (RBAC) ----------
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("SecurityAuditor", policy =>
        policy.RequireRole("SecurityAuditor"));
});

// ---------- Rate Limiting ----------
builder.Services.AddRateLimiter(options =>
{
    options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;

    options.AddPolicy("AnalysisLimiter", httpContext =>
        RateLimitPartition.GetFixedWindowLimiter(
            partitionKey: httpContext.User.Identity?.Name ?? httpContext.Connection.RemoteIpAddress?.ToString() ?? "anonymous",
            factory: _ => new FixedWindowRateLimiterOptions
            {
                PermitLimit = 5,
                Window = TimeSpan.FromMinutes(1),
                QueueLimit = 0
            }));
});

// ---------- Semantic Kernel + Groq ----------
var groqApiKey = builder.Configuration["Groq:ApiKey"]
    ?? throw new InvalidOperationException("Falta Groq:ApiKey en la configuración (user-secrets).");

builder.Services.AddKernel()
    .AddOpenAIChatCompletion(
        modelId: "openai/gpt-oss-120b",
        endpoint: new Uri("https://api.groq.com/openai/v1"),
        apiKey: groqApiKey);

// ---------- Servicios estándar ----------
builder.Services.AddHttpClient<SecAuditAI.Api.Services.WebhookNotifier>();

builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("Default") ?? "Data Source=secaudit.db"));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.UseRateLimiter();

app.UseHttpMetrics();

app.MapControllers();
app.MapMetrics();

app.Run();
