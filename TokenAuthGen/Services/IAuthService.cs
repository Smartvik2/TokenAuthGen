using System.Threading.Tasks;
using TokenAuthGen.DTO;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace TokenAuthGen.Services
{
    public interface IAuthService
    {
        Task<(bool IsSuccess, string Message)> SignUpAsync(signUpDto dto, string? confirmationUrlBase);
        Task<(bool IsSuccess, string Message)> ConfirmEmailAsync(string userId, string token);
        Task<(bool IsSuccess, string TokenOrMessage)> SignInAsync(signInDto dto);
    }
}
