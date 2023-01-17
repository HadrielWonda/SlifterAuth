using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.JwtBearer;

/
public class MessageReceivedContext : ResultContext<JwtBearerOptions>
{
    
    public MessageReceivedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        JwtBearerOptions options)
        : base(context, scheme, options) { }
        
    public string? Token { get; set; }
}
