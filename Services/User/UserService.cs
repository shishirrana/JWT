using System.Security.Claims;

namespace DemoJWT.Services.User
{
    public class UserService : IUserService
    {
        private readonly IHttpContextAccessor _httpContextAccessor;

        public UserService(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public string GetMyName()
        {
            var result = string.Empty;
            if(_httpContextAccessor.HttpContext != null)
            {
                //Injecting the claimtype of user name to get the value.
                result = _httpContextAccessor.HttpContext.User.FindFirstValue(ClaimTypes.Name);
            }
            
            return result;
        }
    }
}
