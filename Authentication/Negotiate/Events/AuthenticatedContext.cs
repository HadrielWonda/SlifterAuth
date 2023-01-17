using Microsoft.AspNetCore.Http;

namespace Microsoft.AspNetCore.Authentication.Negotiate;


public class AuthenticatedContext : ResultContext<NegotiateOptions>
{
    public AuthenticatedContext(
        HttpContext context,
        AuthenticationScheme scheme,
        NegotiateOptions options)
        : base(context, scheme, options) { }
}
