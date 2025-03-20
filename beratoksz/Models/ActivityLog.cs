namespace beratoksz.Models
{
    public class ActivityLog
    {
        public int Id { get; set; }
        public string? UserName { get; set; }
        public string Page { get; set; }
        public DateTime Timestamp { get; set; }
        public string IPAddress { get; set; } // ✅ Kullanıcının IP adresi
        public string UserAgent { get; set; } // ✅ Tarayıcı bilgisi
        public string OS { get; set; } // ✅ İşletim sistemi
        public double Duration { get; set; } // ✅ Sayfada kalma süresi (saniye)


        public string Country { get; set; }
        public string City { get; set; }
        public string Region { get; set; }

    }


}
