using Microsoft.AspNetCore.Http;

namespace SlifterAuth.Authentication.JwtBearer;

public class AuthenticationFailedContext : ResultContext<JwtBearerOptions>
{
    public AuthenticationFailedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        JwtBearerOptions options)
        : base(context, scheme, options) { }

    public Exception Exception { get; set; } = default!;
}
