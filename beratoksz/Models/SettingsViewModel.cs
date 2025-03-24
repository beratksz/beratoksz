namespace beratoksz.Models
{
    public class SettingsViewModel
    {
        public List<SiteSettings> SettingsList { get; set; } = new List<SiteSettings>();
        public SiteSettings CurrentSettings { get; set; } = new SiteSettings();
    }
}
