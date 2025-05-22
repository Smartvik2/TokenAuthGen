namespace TokenAuthGen.Models
{
    public class AccessToken
    {
        public int Id { get; set; }
        public string Token { get; set; } = default!;
        public DateTime Expiry { get; set; }
        public string UserId { get; set; } = default!;
        public User User { get; set; } = default!;
    }

}
