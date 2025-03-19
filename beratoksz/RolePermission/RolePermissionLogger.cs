using Microsoft.Extensions.Logging;

public class RolePermissionLogger
{
    private readonly ILogger<RolePermissionLogger> _logger;

    public RolePermissionLogger(ILogger<RolePermissionLogger> logger)
    {
        _logger = logger;
    }

    public void LogPermissionChange(string action, string role, string path)
    {
        _logger.LogInformation($"[{action}] Role: {role}, Path: {path}");
    }
}
