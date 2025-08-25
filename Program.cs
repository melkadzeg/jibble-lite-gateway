using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using Yarp.ReverseProxy.Configuration;


var builder = WebApplication.CreateBuilder(args);

// JWT auth at the edge
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = builder.Configuration["Jwt:Issuer"],
            ValidAudience = builder.Configuration["Jwt:Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(builder.Configuration["Jwt:Key"]!)),
            ClockSkew = TimeSpan.Zero
        };
        
        o.Events = new JwtBearerEvents
        {
            OnAuthenticationFailed = context =>
            {
                Console.WriteLine($"Authentication failed: {context.Exception.Message}");
                return Task.CompletedTask;
            },
            OnTokenValidated = context =>
            {
                Console.WriteLine("Token validated successfully");
                return Task.CompletedTask;
            }
        };
    });

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("edge-auth", p => p.RequireAuthenticatedUser());
});

// YARP proxy
builder.Services.AddReverseProxy()
    .LoadFromConfig(builder.Configuration.GetSection("ReverseProxy"));

var app = builder.Build();

app.UseAuthentication();
app.UseAuthorization();

app.Use(async (ctx, next) =>
{
    if (ctx.User?.Identity?.IsAuthenticated == true)
    {
        var sub   = ctx.User.FindFirst("sub")?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = ctx.User.FindFirst("email")?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.Email)?.Value;
        var name  = ctx.User.FindFirst("name")?.Value
                    ?? ctx.User.FindFirst(ClaimTypes.Name)?.Value;

        // strip any client-supplied spoofed values, then set ours
        ctx.Request.Headers.Remove("X-User-Id");
        ctx.Request.Headers.Remove("X-User-Email");
        ctx.Request.Headers.Remove("X-User-Name");

        if (!string.IsNullOrEmpty(sub))   ctx.Request.Headers["X-User-Id"]   = sub;
        if (!string.IsNullOrEmpty(email)) ctx.Request.Headers["X-User-Email"] = email;
        if (!string.IsNullOrEmpty(name))  ctx.Request.Headers["X-User-Name"]  = name;

        // (optional) hide JWT from downstream services
        ctx.Request.Headers.Remove("Authorization");
    }

    await next();
});

app.MapReverseProxy();

app.Run();