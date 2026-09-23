using Microsoft.EntityFrameworkCore;

namespace SecAuditAI.Api.Data;

public class AppDbContext : DbContext
{
    public AppDbContext(DbContextOptions<AppDbContext> options) : base(options)
    {
    }

    public DbSet<AuditReport> AuditReports => Set<AuditReport>();
}
