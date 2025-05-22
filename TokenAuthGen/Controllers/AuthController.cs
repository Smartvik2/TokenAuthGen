using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using TokenAuthGen.DTO;
using TokenAuthGen.Services;

namespace TokenAuthGen.Controllers
{
    [ApiController]
    [Route("Api/[Controller]")]
    public class Authcontroller : ControllerBase
    {
        
        private readonly IAuthService _authService;

        public Authcontroller(IAuthService authService)
        {
                _authService = authService;
        }



        /// <summary>
        /// Registers a new user and sends an email confirmation link.
        /// </summary>
        /// <param name="dto">User registration details.</param>
        /// <returns>Success message if signup is successful; otherwise, error details.</returns>
        /// <response code="200">Registration successful, confirmation email sent.</response>
        /// <response code="400">Registration failed due to invalid data.</response>

        [HttpPost("signUp")]
        public async Task<IActionResult> SignUp([FromBody] signUpDto dto)
        {
           var confirmationUrlBase = Url.Action(nameof(ConfirmEmail), "Auth", null, Request.Scheme);
           var (isSuccess, message) = await _authService.SignUpAsync(dto, confirmationUrlBase);
           if (!isSuccess)
               return BadRequest(new { message });

           return Ok(message);
        }



        /// <summary>
        /// Confirms a user's email using userId and token.
        /// </summary>
        /// <param name="userId">User's ID from the confirmation email.</param>
        /// <param name="token">Email confirmation token.</param>
        /// <returns>Success or failure message.</returns>
        /// <response code="200">Email confirmed successfully.</response>
        /// <response code="400">Invalid or expired confirmation token.</response>

        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
           var (isSuccess, message) = await _authService.ConfirmEmailAsync(userId, token);
           if (!isSuccess)
                return BadRequest(message);

             return Ok(message);
        }




        /// <summary>
        /// Authenticates a user and returns a JWT token.
        /// </summary>
        /// <param name="dto">User login details.</param>
        /// <returns>JWT token if authentication is successful; error otherwise.</returns>
        /// <response code="200">Authentication successful.</response>
        /// <response code="401">Invalid username or password.</response>

        [HttpPost("signIn")]
       public async Task<IActionResult> SignIn([FromBody] signInDto dto)
       {
         var (isSuccess, tokenOrMessage) = await _authService.SignInAsync(dto);
         if (!isSuccess)
             return Unauthorized(new { message = tokenOrMessage });

          return Ok(new { token = tokenOrMessage });
       }
     
    }
}
