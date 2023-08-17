namespace DemoJWT
{
    public class RefreshToken
    {
        public string Token { get; set; } = string.Empty;
        //Token Creation time with System time (DateTime.Now initializes the current System Datetime)
        public DateTime Created { get; set; } = DateTime.Now;
        //Expire time of Refresh Token
        public DateTime Expires { get; set; }
    }
}
