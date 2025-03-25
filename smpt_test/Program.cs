using System;
using System.Net;
using System.Net.Mail;
using System.Threading.Tasks;

namespace SmtpTest
{
    class Program
    {
        static async Task Main(string[] args)
        {
            Console.WriteLine("Program başladı."); // Programın başladığını kontrol etmek için

            // SMTP ayarlarını giriyoruz.
            string smtpHost = "smtp.hostinger.com";
            int smtpPort = 465; // Alternatif olarak 587 deneyebilirsin.
            string smtpUsername = "admin@beratoksz.com";
            string smtpPassword = "1903Be1526-"; // Gerçek şifreni buraya gir.
            string emailFromAddress = "no-reply@beratoksz.com";
            string emailFromName = "noreply";
            string recipient = "beratokszhosting@gmail.com"; // Kendi email adresin ya da test için kullandığın adres.

            try
            {
                SmtpClient smtpClient = new SmtpClient(smtpHost)
                {
                    Port = smtpPort,
                    Credentials = new NetworkCredential(smtpUsername, smtpPassword),
                    EnableSsl = true,
                };

                MailMessage mail = new MailMessage()
                {
                    From = new MailAddress(emailFromAddress, emailFromName),
                    Subject = "SMTP Test Email",
                    Body = "Bu bir SMTP test emailidir.",
                    IsBodyHtml = false,
                };
                mail.To.Add(recipient);

                await smtpClient.SendMailAsync(mail);
                Console.WriteLine("Email başarıyla gönderildi!");
            }
            catch (Exception ex)
            {
                Console.WriteLine("Email gönderimi başarısız: " + ex.Message);
            }

            Console.WriteLine("Program bitti."); // Programın bittiğini kontrol etmek için
        }
    }
}
