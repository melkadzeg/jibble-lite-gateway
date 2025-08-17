using System.Security.Claims;

namespace Gateway.Middleware;

public class ForwardUserHeadersMiddleware(RequestDelegate next)
{
    public async Task InvokeAsync(HttpContext ctx)
    {
        Console.WriteLine($"=== MIDDLEWARE START ===");
        Console.WriteLine($"Path: {ctx.Request.Path}");
        Console.WriteLine($"Raw Authorization: '{ctx.Request.Headers.Authorization}'");
        Console.WriteLine($"User.Identity exists: {ctx.User?.Identity != null}");
        Console.WriteLine($"IsAuthenticated: {ctx.User?.Identity?.IsAuthenticated}");
        Console.WriteLine($"Claims count: {ctx.User.Claims.Count()}");
        
        foreach (var claim in ctx.User.Claims)
        {
            Console.WriteLine($"CLAIM {claim.Type} = {claim.Value}");
        }
        
        if (ctx.User?.Identity?.IsAuthenticated == true)
        {
            var userId = ctx.User.FindFirst("sub")?.Value
                         ?? ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var tenantId = ctx.User.FindFirst("tid")?.Value;

            Console.WriteLine($"[Injector] sub={userId ?? "<null>"}, tid={tenantId ?? "<null>"}");

            if (!string.IsNullOrEmpty(userId))  ctx.Request.Headers["X-User-Id"] = userId;
            if (!string.IsNullOrEmpty(tenantId)) ctx.Request.Headers["X-Tenant-Id"] = tenantId;

        }

        await next(ctx);
    }
}