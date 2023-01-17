using System.Globalization;
using System.Linq;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace Microsoft.AspNetCore.Authentication;

internal sealed class JwtBearerConfigureOptions : IConfigureNamedOptions<JwtBearerOptions>
{
    private readonly IAuthenticationConfigurationProvider _authenticationConfigurationProvider;
    private static readonly Func<string, TimeSpan> _invariantTimeSpanParse = 
    (string timespanString) =>
    TimeSpan.Parse(timespanString, CultureInfo.InvariantCulture);

   
    public JwtBearerConfigureOptions(IAuthenticationConfigurationProvider configurationProvider)
    {
        _authenticationConfigurationProvider = configurationProvider;
    }

   
    public void Configure(string? name, JwtBearerOptions options)
    {
        if (string.IsNullOrEmpty(name))
        {
            return;
        }

        var configSection = _authenticationConfigurationProvider.GetSchemeConfiguration(name);

        if (configSection is null || !configSection.GetChildren().Any())
        {
            return;
        }

        var issuer = configSection[nameof(TokenValidationParameters.ValidIssuer)];
        var issuers = configSection.GetSection(nameof(TokenValidationParameters.ValidIssuers)).GetChildren().Select(iss => iss.Value).ToList();
        if (issuer is not null)
        {
            issuers.Add(issuer);
        }
        var audience = configSection[nameof(TokenValidationParameters.ValidAudience)];
        var audiences = configSection.GetSection(nameof(TokenValidationParameters.ValidAudiences)).GetChildren().Select(aud => aud.Value).ToList();
        if (audience is not null)
        {
            audiences.Add(audience);
        }

        options.Authority = configSection[nameof(options.Authority)] ?? options.Authority;
        options.BackchannelTimeout = StringHelpers.ParseValueOrDefault(configSection[nameof(options.BackchannelTimeout)], _invariantTimeSpanParse, options.BackchannelTimeout);
        options.Challenge = configSection[nameof(options.Challenge)] ?? options.Challenge;
        options.ForwardAuthenticate = configSection[nameof(options.ForwardAuthenticate)] ?? options.ForwardAuthenticate;
        options.ForwardChallenge = configSection[nameof(options.ForwardChallenge)] ?? options.ForwardChallenge;
        options.ForwardDefault = configSection[nameof(options.ForwardDefault)] ?? options.ForwardDefault;
        options.ForwardForbid = configSection[nameof(options.ForwardForbid)] ?? options.ForwardForbid;
        options.ForwardSignIn = configSection[nameof(options.ForwardSignIn)] ?? options.ForwardSignIn;
        options.ForwardSignOut = configSection[nameof(options.ForwardSignOut)] ?? options.ForwardSignOut;
        options.IncludeErrorDetails = StringHelpers.ParseValueOrDefault(configSection[nameof(options.IncludeErrorDetails)], bool.Parse, options.IncludeErrorDetails);
        options.MapInboundClaims = StringHelpers.ParseValueOrDefault( configSection[nameof(options.MapInboundClaims)], bool.Parse, options.MapInboundClaims);
        options.MetadataAddress = configSection[nameof(options.MetadataAddress)] ?? options.MetadataAddress;
        options.RefreshInterval = StringHelpers.ParseValueOrDefault(configSection[nameof(options.RefreshInterval)], _invariantTimeSpanParse, options.RefreshInterval);
        options.RefreshOnIssuerKeyNotFound = StringHelpers.ParseValueOrDefault(configSection[nameof(options.RefreshOnIssuerKeyNotFound)], bool.Parse, options.RefreshOnIssuerKeyNotFound);
        options.RequireHttpsMetadata = StringHelpers.ParseValueOrDefault(configSection[nameof(options.RequireHttpsMetadata)], bool.Parse, options.RequireHttpsMetadata);
        options.SaveToken = StringHelpers.ParseValueOrDefault(configSection[nameof(options.SaveToken)], bool.Parse, options.SaveToken);
        options.TokenValidationParameters = new()
        {
            ValidateIssuer = issuers.Count > 0,
            ValidIssuers = issuers,
            ValidateAudience = audiences.Count > 0,
            ValidAudiences = audiences,
            ValidateIssuerSigningKey = true,
            IssuerSigningKeys = GetIssuerSigningKeys(configSection, issuers),
        };
    }

    private static IEnumerable<SecurityKey> GetIssuerSigningKeys(IConfiguration configuration, List<string?> issuers)
    {
        foreach (var issuer in issuers)
        {
            var signingKey = configuration.GetSection("SigningKeys")
                .GetChildren()
                .SingleOrDefault(key => key["Issuer"] == issuer);
            if (signingKey is not null && signingKey["Value"] is string keyValue)
            {
                yield return new SymmetricSecurityKey(Convert.FromBase64String(keyValue));
            }
        }
    }

  
    public void Configure(JwtBearerOptions options)
    {
        Configure(Options.DefaultName, options);
    }
}
