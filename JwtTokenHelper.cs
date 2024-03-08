// JwtTokenHelper
// Shepherd Zhu
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.IdentityModel.Tokens;

public static class JwtTokenHelper
{
    /// <summary>
    /// 从Token中拿出用户Id信息，空字符串意味失败
    /// </summary>
    /// <param name="token"></param>
    /// <returns></returns>
    public static async Task<string> GetUserIdFromToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var result = await tokenHandler.ValidateTokenAsync(
            token,
            new TokenValidationParameters()
            {
                ValidIssuer = Program.builder.Configuration["Jwt:Issuer"],
                ValidAudience = Program.builder.Configuration["Jwt:Audience"],
                IssuerSigningKey = new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(Program.builder.Configuration["Jwt:Key"])
                ),
                ValidateIssuer = true,
                ValidateAudience = true,
                ValidateLifetime = true,
                ValidateIssuerSigningKey = true
            }
        );

        if (!result.IsValid)
        {
            return string.Empty;
        }

        var jwtToken = tokenHandler.ReadJwtToken(token);

        var idClaim = jwtToken.Claims.FirstOrDefault(claim => claim.Type == "Id");
        if (idClaim != null)
        {
            return idClaim.Value;
        }

        return string.Empty;
    }
}
