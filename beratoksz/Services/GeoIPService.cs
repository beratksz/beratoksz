using System.Net;
using System.Net.Http;
using System.Threading.Tasks;
using MaxMind.GeoIP2.Responses;
using MaxMind.GeoIP2;
using Newtonsoft.Json;


    public class GeoIPService
    {
        private readonly DatabaseReader _reader;

        public GeoIPService(IWebHostEnvironment env)
        {
            var dbPath = Path.Combine(env.WebRootPath, "GeoLite2-City.mmdb");
            _reader = new DatabaseReader(dbPath);
        }

        public CityResponse GetLocation(string ipAddress)
        {
            if (IPAddress.TryParse(ipAddress, out var ip))
            {
                return _reader.City(ip);
            }
            return null;
        }
    }
