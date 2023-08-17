using DemoJWT.Services.User;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;

namespace DemoJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        //creating object of user model with static 
        public static User user = new User();

        //HttpContextAccessor
        private readonly IConfiguration _configuration;

        //Dependency Injection
        private readonly IUserService _userService;

        public AuthController(IConfiguration configuration, IUserService userService)
        {
            _configuration = configuration;

            //using Constructor injecting the dependency to access the ClaimTypes service of the user-name.
            _userService = userService;
        }


        [HttpGet, Authorize]
        public ActionResult<string> GetMe()
        {

            var userName = _userService.GetMyName();
            return Ok(userName);
            //To get which user has accessed.
            //var userName = User?.Identity?.Name;

            ////To get the claim name that has accessed.
            //var claimName = User.FindFirstValue(ClaimTypes.Name);

            ////To get the role name that has accessed.
            //var roleName = User.FindFirstValue(ClaimTypes.Role); 
            //return Ok(new
            //{
            //    userName,
            //    //claimName,
            //    //roleName
            //});
        }


        [HttpPost("signup")]
        public async Task<ActionResult<User>> Register(UserDto request)
        {
            //Method CreatePasswordHash
            CreatePasswordHash(request.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.Username = request.Username;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return  Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto response)
        {
            if (user.Username != response.Username)
            {
                return BadRequest("Failed to Login.");
            }

            //Validating if the passwordHash and passwordSalt is equal to the signup and login or not
            if(!VerifyPasswordHash(response.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Password doesn't match.");
            }

            //Creating the token(JWT)
            string token = CreateToken(user);
            //Creating the RefreshToken
            var refreshToken = GenerateRefreshToken();
            //HttpOnly for cookie so that no js can access it.
            SetRefreshToken(refreshToken);
            return Ok(token);
        }


        //New refresh token that will be sent with the cookie.
        [HttpPost("register-token")]
        public async Task<ActionResult<string>> RefreshToken()
        {
            //Getting the refreshToken from cookies to check.
            var refreshToken = Request.Cookies["refreshToken"];
            
            //Checking whether the refreshToken is valid or not / if it is being manipulated 
            if(!user.RefreshToken.Equals(refreshToken))
            {
                return Unauthorized("Invalid Token");
            }
            
            //Validating for the token whether it has expired or not!
            else if(user.TokenExpires < DateTime.Now)
            {
                return Unauthorized("Token has expired");
            }

            //If the refreshToken has expired then generating the new refreshToken
            string token = CreateToken(user);
            var newRefreshToken =  GenerateRefreshToken();
            SetRefreshToken(newRefreshToken);

            return Ok(token);
        }



        //Method to generate the random token and convert it into string of 64bytes
        private RefreshToken GenerateRefreshToken()
        {
            var refreshToken = new RefreshToken
            {
                Token = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64)),
                //Create the token with system date and time.
                Created = DateTime.Now,
                //Expiry date using the Days/Minutes/Hours
                Expires = DateTime.Now.AddDays(1)
            };
            return refreshToken;
        }

        private void SetRefreshToken(RefreshToken newRefreshToken)
        {
            // Create cookie options
            var cookieOptions = new CookieOptions //CookieOptions stores the new refresh tokens.
            {
                HttpOnly = true,             // HttpOnly flag restricts JavaScript access to the cookie
                Expires = newRefreshToken.Expires   // Set the expiration time for the cookie
            };

            // Add the refresh token to the response cookie
            Response.Cookies.Append("refreshToken", newRefreshToken.Token, cookieOptions);

            // Update user's properties with new refresh token information
            user.RefreshToken = newRefreshToken.Token;
            user.TokenCreated = newRefreshToken.Created;
            user.TokenExpires = newRefreshToken.Expires;
        }


        //Method CreateToken to create the token i.e., JWT token
        private string CreateToken(User user)
        {
            //Adding the Claim using the name of the user and using Usernames with Roles
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username),
                //Adding the role of admin to access the data.
                new Claim(ClaimTypes.Role, "Admin")

            };


            //Getting the Secret token from appsettings.json using the IConfiguration in above constructor
            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            //Getting the Signing Credentials
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);

            //define the properties of json web token
            var token = new JwtSecurityToken(
                //Adding the clamis
                claims: claims,
                //Adding the expiration date of token
                expires: DateTime.Now.AddDays(1),
                //Taking the signingCredentials
                signingCredentials: creds);

            //Generate the handler for the token and store it in the value jwt.
            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA256())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }
        
        //To verify the passwordhash is equal to the signup and login or not!
        private bool VerifyPasswordHash(string password,  byte[] passwordHash,  byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA256(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }



    }
}
