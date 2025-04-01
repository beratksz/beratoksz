using beratoksz.Data;
using beratoksz.PerformanceMetrics;
using beratoksz.Hubs;
using beratoksz.Services;
using beratoksz.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using Serilog;
using AspNetCoreRateLimit;
using System.Text;
using System.Security.Claims;
using beratoksz;
using Microsoft.AspNetCore.HttpOverrides;
using DotNetEnv;

DotNetEnv.Env.Load();

var builder = WebApplication.CreateBuilder(args);

// ?? Serilog Konfigürasyonu
Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .WriteTo.File("Logs/app-log-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog((context, services, config) =>
{
    config.ReadFrom.Configuration(context.Configuration)
          .ReadFrom.Services(services)
          .Enrich.FromLogContext();
});

// ?? Veritabaný
var connectionString = Environment.GetEnvironmentVariable("DEFAULT_CONNECTION_STRING")
    ?? builder.Configuration.GetConnectionString("DefaultConnection")
    ?? throw new InvalidOperationException("Veritabaný baðlantý bilgisi bulunamadý.");

// Veritabaný
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(connectionString));

// ?? Identity
builder.Services.AddIdentity<AppUser, AppRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequireLowercase = true;
    options.Password.RequireUppercase = true;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequiredLength = 6;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
    options.Cookie.SameSite = SameSiteMode.Lax;
});

builder.Services.AddScoped<IUserClaimsPrincipalFactory<AppUser>, AdditionalUserClaimsPrincipalFactory>();
builder.Services.AddScoped<RolePermissionService>();
builder.Services.AddHttpContextAccessor();
builder.Services.AddScoped<PageDiscoveryService>();
builder.Services.AddScoped<TwoFactorEmailService>();
builder.Services.AddScoped<UserSecurityService>();
builder.Services.AddScoped<EmailConfirmationService>();
builder.Services.AddScoped<SettingsService>();
builder.Services.AddScoped<PasswordResetEmailService>();
builder.Services.AddScoped<SmsService>();
builder.Services.AddSingleton<WhatsAppService>();

// ?? Rate Limiting
builder.Services.AddOptions();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.AddInMemoryRateLimiting();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

builder.Services.Configure<DataProtectionTokenProviderOptions>(opt =>
{
    opt.TokenLifespan = TimeSpan.FromHours(3); // 3 saat geçerli
});

builder.Services.AddHttpClient("ApiClient", client =>
{
    var apiBaseUrl = builder.Configuration["ApiSettings:BaseUrl"];
    client.BaseAddress = new Uri(apiBaseUrl);
});
// ?? GeoIP
builder.Services.AddSingleton<GeoIPService>();

// ?? SignalR
builder.Services.AddSignalR(options =>
{
    options.KeepAliveInterval = TimeSpan.FromSeconds(15);
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30);
});

// ?? Performans servisi
builder.Services.AddHostedService<PerformanceMetricsService>();

builder.Configuration["JwtSettings:Secret"] = Environment.GetEnvironmentVariable("JWT_SECRET");

// ?? JWT
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(JwtBearerDefaults.AuthenticationScheme, options =>
{
    if (string.IsNullOrWhiteSpace(Environment.GetEnvironmentVariable("JWT_SECRET")))
    {
        throw new Exception("JWT_SECRET ortam deðiþkeni tanýmlý deðil! .env dosyasýný kontrol et.");
    }

    var jwt = builder.Configuration.GetSection("JwtSettings");

    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = jwt["ValidIssuer"],
        ValidAudience = jwt["ValidAudience"],
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwt["Secret"])),
        ClockSkew = TimeSpan.Zero
    };
});

// ?? Diðer servisler
builder.Services.AddMemoryCache();
builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(5);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

builder.Services.AddControllersWithViews();
builder.Services.AddResponseCaching();
builder.Services.AddHealthChecks();
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", policy =>
        policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
});

// ?? Swagger
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. Örn: 'Bearer {token}'",
        Name = "Authorization",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });
    c.AddSecurityRequirement(new Microsoft.OpenApi.Models.OpenApiSecurityRequirement {
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
                In = Microsoft.OpenApi.Models.ParameterLocation.Header
            }, new List<string>()
        }
    });
});

var app = builder.Build();

// ?? Middleware Pipeline
app.UseSwagger();
app.UseSwaggerUI(c => c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1"));

app.UseExceptionHandler("/Error");
app.UseStatusCodePagesWithReExecute("/Error/{0}");
app.UseHttpsRedirection();
app.UseStaticFiles();

app.Use(async (context, next) =>
{
    var path = context.Request.Path.ToString().ToLower();
    if (path == "/" || path == "/home")
    {
        Console.WriteLine($"?? PATH DÜZELTÝLDÝ: {path} ? /Home/Index");
        context.Request.Path = "/Home/Index";
    }
    await next();
});


var forwardedHeaderOptions = new ForwardedHeadersOptions
{
    ForwardedHeaders = ForwardedHeaders.XForwardedFor | ForwardedHeaders.XForwardedProto
};
forwardedHeaderOptions.KnownNetworks.Clear(); // Varsayýlan güvenlik kontrollerini kaldýrabilirsiniz
forwardedHeaderOptions.KnownProxies.Clear();

app.UseForwardedHeaders(forwardedHeaderOptions);



app.UseRouting();
app.UseResponseCaching();
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.UseIpRateLimiting();
app.UseSession();

app.UseMiddleware<PerformanceMetricsMiddleware>();
app.UseMiddleware<ActivityLoggingMiddleware>();
app.UseMiddleware<RolePermissionMiddleware>();
app.UseMiddleware<AutoDiscoverMiddleware>();

app.MapHub<StatusHub>("/statusHub");

// ?? Veritabaný Seeding (Admin ve roller)
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await DbInitializer.InitializeAsync(services);
}

// ?? Route Discovery ve Otomatik Yetkilendirme


using (var scope = app.Services.CreateScope())
{
    var provider = scope.ServiceProvider;
    var db = provider.GetRequiredService<ApplicationDbContext>();
    var pageDiscovery = provider.GetRequiredService<PageDiscoveryService>();
    var seeder = new RolePermissionSeeder(db);

    var discoveredEndpoints = pageDiscovery.GetAllPages();
    discoveredEndpoints.AddRange(HubRoutes.All); // Hub yollarýný da dahil et

    seeder.SeedPermissions(discoveredEndpoints);
}


// ?? Endpoint mapping
app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.MapHealthChecks("/health");

app.Run();
