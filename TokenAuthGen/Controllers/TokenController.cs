using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using TokenAuthGen.DTO;
using TokenAuthGen.Services;

namespace TokenAuthGen.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class TokenController : ControllerBase 
    {
        private readonly ITokenService _tokenService;

        public TokenController(ITokenService tokenService)
        {
            _tokenService = tokenService;
        }



        /// <summary>
        /// Generates a 6-digit alphanumeric token with a specified expiry.
        /// </summary>
        /// <param name="dto">The token generation details including expiry date.</param>
        /// <returns>Returns the generated token and its expiry if successful; otherwise, a bad request with error message.</returns>
        /// <response code="200">Token generated successfully.</response>
        /// <response code="400">Invalid request data or failure to generate token.</response>
        /// <response code="401">Unauthorized. User must be authenticated.</response>

        [Authorize]
        [HttpPost("GenerateToken")]
        public async Task<IActionResult> GenerateToken([FromBody] GenerateToken dto)
        {
            var (isSuccess, message, data) = await _tokenService.GenerateTokenAsync(User, dto);
            if (!isSuccess)
                return BadRequest(new { message });

            return Ok(data);
        }



        /// <summary>
        /// Verifies whether a provided token is valid and belongs to the authenticated user.
        /// </summary>
        /// <param name="dto">The token verification details including the token string.</param>
        /// <returns>Returns a success message if token is valid; otherwise, bad request with error message.</returns>
        /// <response code="200">Token is valid.</response>
        /// <response code="400">Token is invalid or expired.</response>
        /// <response code="401">Unauthorized. User must be authenticated.</response>

        [Authorize]
        [HttpPost("verify")]
        public async Task<IActionResult> VerifyToken([FromBody] VerifyToken dto)
        {
            var (isSuccess, message) = await _tokenService.VerifyTokenAsync(User, dto);
            if (!isSuccess)
                return BadRequest(new { message });

            return Ok(new { message });
        }
    }
}
