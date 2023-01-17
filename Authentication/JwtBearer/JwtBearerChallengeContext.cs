using Microsoft.AspNetCore.Http;

namespace SlifterAuth.Authentication.JwtBearer;

public class JwtBearerChallengeContext : PropertiesContext<JwtBearerOptions>
{
   
    public JwtBearerChallengeContext(
        HttpContext context,
        AuthenticationScheme scheme,
        JwtBearerOptions options,
        AuthenticationProperties properties)
        : base(context, scheme, options, properties) { }

    public Exception? AuthenticateFailure { get; set; }

    public string? Error { get; set; }

  
    public string? ErrorDescription { get; set; }

  
    public string? ErrorUri { get; set; }

    public bool Handled { get; private set; }

  
    public void HandleResponse() => Handled = true;
}
