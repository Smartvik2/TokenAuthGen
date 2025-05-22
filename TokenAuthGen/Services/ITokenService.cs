using System.Security.Claims;
using TokenAuthGen.DTO;

namespace TokenAuthGen.Services
{
    public interface ITokenService
    {
        Task<(bool IsSuccess, string Message, object? Data)> GenerateTokenAsync(ClaimsPrincipal user, GenerateToken dto);
        Task<(bool IsSuccess, string Message)> VerifyTokenAsync(ClaimsPrincipal user, VerifyToken dto);
    }
}
