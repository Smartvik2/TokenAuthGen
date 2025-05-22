using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Identity;
using System.Security.Claims;
using TokenAuthGen.Data;
using TokenAuthGen.DTO;
using TokenAuthGen.Models;
using Microsoft.EntityFrameworkCore;


namespace TokenAuthGen.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TokenController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly AppDbContext _context;

        public TokenController(UserManager<User> userManager, AppDbContext context)
        {
            _userManager = userManager;
            _context = context;
        }

        /// <summary>
        /// Generates a 6-digit alphanumeric token that expires within a specified timeframe (maximum 3 days).
        /// </summary>
        /// <param name="dto">Contains the expiry date for the token.</param>
        /// <returns>Returns the generated token and its expiry date.</returns>
        [Authorize]
        [HttpPost("GenerateToken")]
        public async Task<IActionResult> GenerateToken([FromBody] GenerateToken dto)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null)
                return Unauthorized();
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return Unauthorized("User not found.");

            if (dto.ExpiryDate <= DateTime.UtcNow)
                return BadRequest("Expiry date must be in the future.");

            if ((dto.ExpiryDate - DateTime.UtcNow).TotalDays > 3)
                return BadRequest("Token expiry cannot exceed 3 days.");

           

            var token = Generate6DigitAlphaNumeric();

            var accessToken = new AccessToken
            {
                Token = token,
                Expiry = dto.ExpiryDate,
                UserId = userId
            };

            _context.AccessTokens.Add(accessToken);
            await _context.SaveChangesAsync();

            return Ok(new { token = token, expires = dto.ExpiryDate });
        }

        /// <summary>
        /// Verifies the validity and ownership of a token.
        /// </summary>
        /// <param name="dto">Contains the token to be verified.</param>
        /// <returns>200 OK if token is valid, 404 if not found, 400 if expired.</returns>
        [Authorize]
        [HttpPost("verify")]
        public async Task<IActionResult> VerifyToken([FromBody] VerifyToken dto)
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null) return Unauthorized();

            var token = await _context.AccessTokens
                .FirstOrDefaultAsync(t => t.Token == dto.Token && t.UserId == userId);

            if (token == null) return NotFound("Token not found or does not belong to you.");
            if (token.Expiry < DateTime.UtcNow) return BadRequest("Token has expired.");

            return Ok("Token is valid.");
        }

        /// <summary>
        /// Generates a random 6-character alphanumeric token.
        /// </summary>
        /// <returns>A string token composed of uppercase letters and digits.</returns>
        private string Generate6DigitAlphaNumeric()
        {
            var chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            var random = new Random();
            return new string(Enumerable.Range(0, 6)
                .Select(_ => chars[random.Next(chars.Length)]).ToArray());
        }

        

    }
}
