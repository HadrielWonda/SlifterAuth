using Microsoft.AspNetCore.Http;

namespace SlifterAuth.Authentication.JwtBearer;

public class ForbiddenContext : ResultContext<JwtBearerOptions>
{
    public ForbiddenContext(
        HttpContext context,
        AuthenticationScheme scheme,
        JwtBearerOptions options)
        : base(context, scheme, options) { }
}
