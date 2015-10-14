using System;
using System.Collections.Generic;
using System.IdentityModel.Protocols.WSTrust;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Claims;
using System.ServiceModel.Security.Tokens;
using System.Text;
using System.Threading.Tasks;

namespace AuthorizeRole
{
    public class Authorizer : IAuthorizer
    {
        public bool VerifyToken(string token, ClientEntity client)
        {
            var secretKey = Convert.FromBase64String(client.SecurityKey);
            var tokenHandler = new JwtSecurityTokenHandler();

            var validationParameters = new TokenValidationParameters()
            {
                ValidIssuer = client.RowKey,
                ValidAudience = client.Audience,
                IssuerSigningToken = new BinarySecretSecurityToken(secretKey)
            };

            try
            {
                SecurityToken securityToken;
                tokenHandler.ValidateToken(token, validationParameters, out securityToken);
                return true;
            }
            catch (Exception e)
            {
                Console.WriteLine("Error {0}", e.Message);
                return false;
            }
        }

        public string BearerToken(ClientEntity client)
        {
            var signatureAlgorithm = "http://www.w3.org/2001/04/xmldsig-more#hmac-sha256";
            var digestAlgorithm = "http://www.w3.org/2001/04/xmlenc#sha256";

            var securityKey = Convert.FromBase64String(client.SecurityKey);
            var inMemKey = new InMemorySymmetricSecurityKey(securityKey);

            ClaimsIdentity identity = new ClaimsIdentity();
            identity.AddClaim(new Claim("scope", "full"));

            JwtSecurityTokenHandler handler = new JwtSecurityTokenHandler();
            SecurityToken securityToken = handler.CreateToken(new SecurityTokenDescriptor()
                {
                    TokenType = "Bearer",
                    Lifetime = new Lifetime(DateTime.UtcNow, DateTime.UtcNow.AddHours(1)),
                    SigningCredentials = new SigningCredentials(inMemKey, signatureAlgorithm, digestAlgorithm),
                    //This data I would get by matching the jwtSecurityToken.Audience to database or something
                    TokenIssuerName = "AuthorizationServer",
                    AppliesToAddress = client.Audience,
                    Subject = identity
                }
            );

            return handler.WriteToken(securityToken);
        }
    }
}
