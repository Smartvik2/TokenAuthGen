using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using System.Security.Claims;
using TokenAuthGen.Data;
using TokenAuthGen.DTO;
using TokenAuthGen.Models;

namespace TokenAuthGen.Services
{
    public class TokenService : ITokenService
    {
        private readonly UserManager<User> _userManager;
        private readonly AppDbContext _context;

        public TokenService(UserManager<User> userManager, AppDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        public async Task<(bool IsSuccess, string Message, object? Data)> GenerateTokenAsync(ClaimsPrincipal userPrincipal, GenerateToken dto)
        {
            var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                return (false, "Unauthorized", null);

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return (false, "User not found", null);

            if (dto.ExpiryDate <= DateTime.UtcNow)
                return (false, "Expiry date must be in the future.", null);

            if ((dto.ExpiryDate - DateTime.UtcNow).TotalDays > 3)
                return (false, "Token expiry cannot exceed 3 days.", null);

            var token = Generate6DigitAlphaNumeric();

            var accessToken = new AccessToken
            {
                Token = token,
                Expiry = dto.ExpiryDate,
                UserId = userId
            };

            _context.AccessTokens.Add(accessToken);
            await _context.SaveChangesAsync();

            return (true, "Token generated", new { token, expires = dto.ExpiryDate });
        }

        public async Task<(bool IsSuccess, string Message)> VerifyTokenAsync(ClaimsPrincipal userPrincipal, VerifyToken dto)
        {
            var userId = userPrincipal.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                return (false, "Unauthorized");

            var token = await _context.AccessTokens
                .FirstOrDefaultAsync(t => t.Token == dto.Token && t.UserId == userId);

            if (token == null)
                return (false, "Token not found or does not belong to you.");

            if (token.Expiry < DateTime.UtcNow)
                return (false, "Token has expired.");

            return (true, "Token is valid.");
        }

        private string Generate6DigitAlphaNumeric()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Range(0, 6)
                .Select(_ => chars[random.Next(chars.Length)]).ToArray());
        }

    }
}
