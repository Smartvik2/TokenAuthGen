using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using TokenAuthGen.DTO;
using TokenAuthGen.Models;
using TokenAuthGen.Services;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace TokenAuthGen.Controllers
{
    [ApiController]
    [Route("Api/[Controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<User> _userManager;
        private readonly IConfiguration _config;
        private readonly IEmailService _emailService;

        public AuthController(UserManager<User> userManager, IConfiguration config, IEmailService emailService)
        {
            _userManager = userManager;
            _config = config;
            _emailService = emailService;
        }

        /// <summary>
        /// Registers a new user and sends an email confirmation link.
        /// </summary>
        /// <param name="dto">Sign up details including email and password.</param>
        /// <returns>200 OK with success message or 400 BadRequest if user exists or validation fails.</returns>
        
        //Api/Auth/signUp
        [HttpPost("signUp")]
        public async Task<IActionResult> SignUp([FromBody]signUpDto dto)
        {
            var existingUser = await _userManager.FindByEmailAsync(dto.Email);
            if (existingUser != null)
                return BadRequest(new { message = "User already exists" });
            var user = new User
            {
                UserName = dto.Email,
                Email = dto.Email
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            //Generate email confirmation token
            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var confirmationLink = Url.Action(nameof(ConfirmEmail), "Auth",
                new { userId = user.Id, token }, Request.Scheme);

            //Mailkik sending logic
            //Console.WriteLine($"Email Confirmation Link : {confirmationLink}");
            var body = $@"
                 <h3>Welcome To My Site! </h3>
                 <p>Please confirm your email by clicking the link below:</p>
                 <a href='{confirmationLink}'>Confirm Email </a>";

            await _emailService.SendEmailAsync(user.Email, "Confirm Your Email", body);
            return Ok("Registration successful! Please check your email to confirm.");

        }

        /// <summary>
        /// Confirms user's email using userId and token.
        /// </summary>
        /// <param name="userId">The user's ID.</param>
        /// <param name="token">The confirmation token.</param>
        /// <returns>200 OK if confirmed; 400 if invalid; 404 if user not found.</returns>
        
        [HttpGet("confirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return NotFound("User not found.");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return result.Succeeded ? Ok("Email confirmed!") : BadRequest("Invalid Confirmation token");
        }

        /// <summary>
        /// Registers a new user and sends an email confirmation link.
        /// </summary>
        /// <param name="dto">Sign up details including email and password.</param>
        /// <returns>200 OK with success message or 400 BadRequest if user exists or validation fails.</returns>
        [HttpPost("signIn")]
        public async Task<IActionResult> SignIn([FromBody] signInDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return Unauthorized(new { message = "Invalid entry" });
            if (user.Email != dto.Email)
                return Unauthorized(new { message = "incorrect Email" });
            if (!await _userManager.IsEmailConfirmedAsync(user))
                return Unauthorized(new { message = "Please confirm your email" });
            if (!await _userManager.CheckPasswordAsync(user, dto.Password))
                return Unauthorized(new { message = "Incorrect password." });

            var token = GenerateJwtToken(user);

            return Ok(new { token});
        }

        /// <summary>
        /// Generates a JWT token for the authenticated user.
        /// </summary>
        /// <param name="user">The authenticated user.</param>
        /// <returns>A JWT token string.</returns>
        private string GenerateJwtToken(IdentityUser user)
        {
            var jwtSettings = _config.GetSection("Jwt");

            var keyString = jwtSettings["Key"];
            if (string.IsNullOrEmpty(keyString))
                throw new Exception("JWT Key is missing in configuration.");

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(keyString));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var issuer = jwtSettings["Issuer"];
            var audience = jwtSettings["Audience"];

            var expiryMinutesString = jwtSettings["ExpiryInMinutes"];
            if (!int.TryParse(expiryMinutesString, out int expiryMinutes))
            {
                expiryMinutes = 60; // default to 60 minutes if parsing fails
            }

            var claims = new[]
            {
            new Claim(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.Email ?? "")
            };

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(expiryMinutes),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }


    }
}
