using System.IdentityModel.Tokens.Jwt;
using System.Net.Http;
using Microsoft.IdentityModel.Protocols;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.IdentityModel.Tokens;

namespace SlifterAuth.Authentication.JwtBearer;


public class JwtBearerOptions : AuthenticationSchemeOptions
{
    private readonly JwtSecurityTokenHandler _defaultHandler = new JwtSecurityTokenHandler();

  
    public JwtBearerOptions()
    {
        SecurityTokenValidators = new List<ISecurityTokenValidator> { _defaultHandler };
    }

    
    public bool RequireHttpsMetadata { get; set; } = true;

    public string MetadataAddress { get; set; } = default!;

    public string? Authority { get; set; }

    public string? Audience { get; set; }

    public string Challenge { get; set; } = JwtBearerDefaults.AuthenticationScheme;

    public new JwtBearerEvents Events
    {
        get { return (JwtBearerEvents)base.Events!; }
        set { base.Events = value; }
    }

 
    public HttpMessageHandler? BackchannelHttpHandler { get; set; }

    public HttpClient Backchannel { get; set; } = default!;

    public TimeSpan BackchannelTimeout { get; set; } = TimeSpan.FromMinutes(1);

    public OpenIdConnectConfiguration? Configuration { get; set; }

    public IConfigurationManager<OpenIdConnectConfiguration>? ConfigurationManager { get; set; }

    public bool RefreshOnIssuerKeyNotFound { get; set; } = true;

    public IList<ISecurityTokenValidator> SecurityTokenValidators { get; private set; }

    public TokenValidationParameters TokenValidationParameters { get; set; } = new TokenValidationParameters();

    public bool SaveToken { get; set; } = true;

    public bool IncludeErrorDetails { get; set; } = true;

    public bool MapInboundClaims
    {
        get => _defaultHandler.MapInboundClaims;
        set => _defaultHandler.MapInboundClaims = value;
    }

 
    public TimeSpan AutomaticRefreshInterval { get; set; } = ConfigurationManager<OpenIdConnectConfiguration>.DefaultAutomaticRefreshInterval;

    public TimeSpan RefreshInterval { get; set; } = ConfigurationManager<OpenIdConnectConfiguration>.DefaultRefreshInterval;
}
