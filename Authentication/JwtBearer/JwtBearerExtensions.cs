using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.DependencyInjection;

namespace SlifterAuth.Authentication.JwtBearer;

public static class JwtBearerExtensions
{
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder)
        => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, _ => { });

  
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, string authenticationScheme)
        => builder.AddJwtBearer(authenticationScheme, _ => { });

  
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder, Action<JwtBearerOptions> configureOptions)
        => builder.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, configureOptions);

  
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder,
    string authenticationScheme,
    Action<JwtBearerOptions> configureOptions)
        => builder.AddJwtBearer(authenticationScheme, displayName: null, configureOptions: configureOptions);

  
    public static AuthenticationBuilder AddJwtBearer(this AuthenticationBuilder builder,
    string authenticationScheme,
    string? displayName,
    Action<JwtBearerOptions> configureOptions)
    {
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IConfigureOptions<JwtBearerOptions>, JwtBearerConfigureOptions>());
        builder.Services.TryAddEnumerable(ServiceDescriptor.Singleton<IPostConfigureOptions<JwtBearerOptions>, JwtBearerPostConfigureOptions>());
        return builder.AddScheme<JwtBearerOptions, JwtBearerHandler>(authenticationScheme, displayName, configureOptions);
    }
}
