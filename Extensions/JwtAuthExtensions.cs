// USING stays the same
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

namespace Gateway.Extensions;

public static class JwtAuthExtensions
{
    public static IServiceCollection AddGatewayJwt(this IServiceCollection services, IConfiguration cfg)
    {
        var issuer   = cfg["Jwt:Issuer"]   ?? throw new InvalidOperationException("Jwt:Issuer missing");
        var audience = cfg["Jwt:Audience"] ?? throw new InvalidOperationException("Jwt:Audience missing");
        var keyRaw   = cfg["Jwt:Key"]      ?? throw new InvalidOperationException("Jwt:Key missing");
        var key      = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyRaw));

        // keep "sub" as "sub"
        JwtSecurityTokenHandler.DefaultInboundClaimTypeMap.Clear();

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
            options.DefaultChallengeScheme    = JwtBearerDefaults.AuthenticationScheme;
        })
        .AddJwtBearer(o =>
        {
            o.RequireHttpsMetadata = false;
            o.SaveToken = true;

            o.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = issuer,

                ValidateAudience = true,
                ValidAudience = audience,

                ValidateIssuerSigningKey = true,
                IssuerSigningKey = key,

                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromMinutes(1),

                NameClaimType = JwtRegisteredClaimNames.Sub
            };

            o.Events = new JwtBearerEvents
            {
                OnAuthenticationFailed = ctx =>
                {
                    Console.WriteLine($"JWT FAILED: {ctx.Exception.Message}");
                    return Task.CompletedTask;
                },
                OnTokenValidated = ctx =>
                {
                    var sub = ctx.Principal?.FindFirst("sub")?.Value;
                    var tid = ctx.Principal?.FindFirst("tid")?.Value;
                    Console.WriteLine($"JWT OK: sub={sub}, tid={tid}");
                    return Task.CompletedTask;
                }
            };
        });

        services.AddAuthorization();
        return services;
    }
}
