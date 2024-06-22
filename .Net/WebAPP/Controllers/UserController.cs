using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using System.Text;
using System.Text.RegularExpressions;
using WebAPP.Context;
using WebAPP.Helpers;
using WebAPP.Models;

namespace WebAPP.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        private readonly AppDbContext _authContext;
        public UserController(AppDbContext appDbContext)
        {
            _authContext = appDbContext;
        }

        [HttpPost("authenticate")]
        public async Task<IActionResult> Authenticate([FromBody] User userObj)
        {
            if (userObj == null)
                return BadRequest();

            var user = await _authContext.Users
                .FirstOrDefaultAsync(x => x.UserName == userObj.UserName
                && x.Password == userObj.Password);
            if (user == null)
                return NotFound(new {Message = "User not found!"});

            return Ok(new
            {
                Message = "Login Sucess"
            });
        }

        [HttpPost("register")]
        public async Task<IActionResult> RegisterUser([FromBody] User userObj)
        {
            if(userObj == null)
                return BadRequest();
            if(string.IsNullOrWhiteSpace(userObj.UserName))
                return BadRequest();
            //Check username
            if(await CheckUserNameExist(userObj.UserName))
                return BadRequest(new {Message = "User Alredy exist"});

            //Check Email
            if (await CheckEmailExist(userObj.Email))
                return BadRequest(new { Message = "Email Alredy exist" });

            //Check Password strength
            var pass = CheckPasswordStrength(userObj.Password);
            if(!string.IsNullOrEmpty(pass))
                return BadRequest(new {Message = $"Pass {pass.ToString()}" });

            userObj.Password = PasswordHasher.HashPassword(userObj.Password);
            userObj.Role = "User";
            userObj.Token = "";
            await _authContext.Users.AddAsync(userObj);
            await _authContext.SaveChangesAsync();

            return Ok(new
            {
                Message = "User Registered!"
            });
        }

        private async Task<bool> CheckUserNameExist(string userName)
            => await _authContext.Users.AnyAsync(x => x.UserName == userName);

        private async Task<bool> CheckEmailExist(string email)
            => await _authContext.Users.AnyAsync(x => x.Email == email);
    
        private string CheckPasswordStrength(string password)
        {
            StringBuilder sb = new StringBuilder();
            if(password.Length < 8)
            {
                sb.Append("Minimum length should be 8"+ Environment.NewLine);
            }
            if((Regex.IsMatch(password, "[a-z]") && Regex.IsMatch(password,"[A-Z]") && Regex.IsMatch(password, "[0-9]")))
            {
                sb.Append("Password Should be alphanumeric" + Environment.NewLine);
            }
            //if(!Regex.IsMatch(password, "[<,>,@]"))
            //    sb.Append("Password should contain special ch" +Environment.NewLine);
        
            return sb.ToString();
        }
    }
}
