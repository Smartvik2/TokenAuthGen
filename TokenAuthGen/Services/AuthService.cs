using Microsoft.AspNetCore.Identity;
using TokenAuthGen.DTO;
using TokenAuthGen.Helper;
using TokenAuthGen.Models;

namespace TokenAuthGen.Services
{
    public class AuthService : IAuthService
    {
        private readonly UserManager<User> _userManager;
        private readonly IEmailService _emailService;
        private readonly jwtGenerateToken _jwtGenerateToken;
        private readonly IConfiguration _configuration;

        public AuthService(
            UserManager<User> userManager,
            IEmailService emailService,
            jwtGenerateToken jwtGenerateToken,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _emailService = emailService;
            _jwtGenerateToken = jwtGenerateToken;
            _configuration = configuration;
        }



        public async Task<(bool IsSuccess, string Message)> SignUpAsync(signUpDto dto, string? confirmationUrlBase)
        {
            var existingUser = await _userManager.FindByEmailAsync(dto.Email);
            if (existingUser != null)
                return (false, "User already exists");

            var user = new User
            {
                UserName = dto.Email,
                Email = dto.Email
            };

            var result = await _userManager.CreateAsync(user, dto.Password);
            if (!result.Succeeded)
            {
                var errorMessages = result.Errors.Select(e => e.Description);
                return (false, string.Join("; ", errorMessages));
            }
                //return (false, string.Join("; ", errorMessages));

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);

            // Compose confirmation link from base URL
            var confirmationLink = $"{confirmationUrlBase}?userId={user.Id}&token={Uri.EscapeDataString(token)}";

            var body = $@"
                <h3>Welcome To My Site!</h3>
                <p>Please confirm your email by clicking the link below:</p>
                <a href='{confirmationLink}'>Confirm Email</a>";

            await _emailService.SendEmailAsync(user.Email, "Confirm Your Email", body);

            return (true, "Registration successful! Please check your email to confirm.");
        }


        public async Task<(bool IsSuccess, string Message)> ConfirmEmailAsync(string userId, string token)
        {
            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                return (false, "User not found.");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            return (result.Succeeded, result.Succeeded ? "Email confirmed!" : "Invalid confirmation token");
        }

        public async Task<(bool IsSuccess, string TokenOrMessage)> SignInAsync(signInDto dto)
        {
            var user = await _userManager.FindByEmailAsync(dto.Email);
            if (user == null)
                return (false, "Invalid entry");

            if (user.Email != dto.Email)
                return (false, "Incorrect email");

            if (!await _userManager.IsEmailConfirmedAsync(user))
                return (false, "Please confirm your email");

            if (!await _userManager.CheckPasswordAsync(user, dto.Password))
                return (false, "Incorrect password.");

            var token = _jwtGenerateToken.GenerateJwtToken(user);

            return (true, token);
        }
    }
    
}
