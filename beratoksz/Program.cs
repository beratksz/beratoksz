using beratoksz.Data;
using beratoksz.PerformanceMetrics;
using beratoksz.Hubs;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Serilog;
using System.Text;
using beratoksz;
using AspNetCoreRateLimit;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()  // Terminale yazdýr
    .WriteTo.File("Logs/app-log-.txt", rollingInterval: RollingInterval.Day) // ?? Günlük log dosyasý oluþtur
    .CreateLogger();

builder.Host.UseSerilog();

// Production loglama için Serilog
builder.Host.UseSerilog((context, services, configuration) =>
    configuration.ReadFrom.Configuration(context.Configuration)
                 .ReadFrom.Services(services)
                 .Enrich.FromLogContext());

// SQL Server baðlantýsý
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity yapýlandýrmasý
builder.Services.AddIdentity<IdentityUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Custom ClaimsPrincipalFactory (rol claim'lerini eklemek için)
builder.Services.AddScoped<IUserClaimsPrincipalFactory<IdentityUser>, AdditionalUserClaimsPrincipalFactory>();

builder.Services.AddMemoryCache();
builder.Services.AddControllersWithViews();
builder.Services.AddResponseCaching();
builder.Services.AddHealthChecks();

// SignalR servisini ekleyin
builder.Services.AddSignalR(options =>
{
    options.KeepAliveInterval = TimeSpan.FromSeconds(15); // ? Baðlantý kontrol süresi
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30); // ? Client baðlantýsý düþtüðünde timeout süresi
});

// Background service: Performans metriklerini toplayan servisi ekleyin
builder.Services.AddHostedService<PerformanceMetricsService>();


// Identity cookie ayarlarý
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
    options.LoginPath = "/Account/Login";
    options.LogoutPath = "/Account/Logout";
});

// Authentication ayarlarý – Identity'nin default cookie'si kullanýlýyor.
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
})
.AddJwtBearer("Jwt", options =>
{
    var jwtConfig = builder.Configuration.GetSection("JWT");
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwtConfig["ValidIssuer"],
        ValidAudience = jwtConfig["ValidAudience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["Secret"]))
    };
});

builder.Services.Configure<IpRateLimitOptions>(options =>
{
    options.GeneralRules = new List<RateLimitRule>
    {
        new RateLimitRule
        {
            Endpoint = "*",
            Limit = 100,
            Period = "1m" // ? Her IP için 1 dakikada 100 istek sýnýrý
        }
    };
});
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

builder.Services.AddSingleton<GeoIPService>();


// Swagger (API dokümantasyonu)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Örneðin: \"Bearer {token}\"",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    options.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement()
    {
        {
            new Microsoft.OpenApi.Models.OpenApiSecurityScheme
            {
                Reference = new Microsoft.OpenApi.Models.OpenApiReference
                {
                    Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme,
                    Id = "Bearer"
                },
                Scheme = "oauth2",
                Name = "Bearer",
                In = Microsoft.OpenApi.Models.ParameterLocation.Header,
            },
            new List<string>()
        }
    });
});

var app = builder.Build();

// Production ortamý için hata yönetimi
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    app.UseHsts();
}
app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseResponseCaching();
app.UseRouting();
app.MapHealthChecks("/health");
app.UseAuthentication();
app.UseAuthorization();

// SignalR hub'ý
app.MapHub<StatusHub>("/statusHub");

// Performans metrikleri middleware
app.UseMiddleware<PerformanceMetricsMiddleware>();
app.UseMiddleware<ActivityLoggingMiddleware>();

// Swagger middleware'leri
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
        c.RoutePrefix = string.Empty;
    });
}

// Routing: Areas ve default route
app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

// Seeding: Admin ve roller oluþturuluyor
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await DbInitializer.InitializeAsync(services);
}

app.Run();
