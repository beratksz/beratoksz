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
using beratoksz.Services;
using beratoksz.Models;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()  // Terminale yazd�r
    .WriteTo.File("Logs/app-log-.txt", rollingInterval: RollingInterval.Day) // ?? G�nl�k log dosyas� olu�tur
    .CreateLogger();

builder.Host.UseSerilog();

// Production loglama i�in Serilog
builder.Host.UseSerilog((context, services, configuration) =>
    configuration.ReadFrom.Configuration(context.Configuration)
                 .ReadFrom.Services(services)
                 .Enrich.FromLogContext());

// SQL Server ba�lant�s�
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Identity yap�land�rmas�
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

// Custom ClaimsPrincipalFactory (rol claim'lerini eklemek i�in)
builder.Services.AddScoped<IUserClaimsPrincipalFactory<AppUser>, AdditionalUserClaimsPrincipalFactory>();

builder.Services.AddMemoryCache();
builder.Services.AddControllersWithViews();
builder.Services.AddResponseCaching();
builder.Services.AddHealthChecks();


builder.Services.AddDistributedMemoryCache();
builder.Services.AddSession(options =>
{
    options.IdleTimeout = TimeSpan.FromMinutes(5);
    options.Cookie.HttpOnly = true;
    options.Cookie.IsEssential = true;
});

// SignalR servisini ekleyin
builder.Services.AddSignalR(options =>
{
    options.KeepAliveInterval = TimeSpan.FromSeconds(15); // ? Ba�lant� kontrol s�resi
    options.ClientTimeoutInterval = TimeSpan.FromSeconds(30); // ? Client ba�lant�s� d��t���nde timeout s�resi
});

// Background service: Performans metriklerini toplayan servisi ekleyin
builder.Services.AddHostedService<PerformanceMetricsService>();

builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowAll", builder =>
    {
        builder.AllowAnyOrigin()
               .AllowAnyMethod()
               .AllowAnyHeader();
    });
});


builder.Services.AddOptions();
builder.Services.Configure<IpRateLimitOptions>(builder.Configuration.GetSection("IpRateLimiting"));
builder.Services.AddInMemoryRateLimiting();
builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();
builder.Services.AddScoped<TwoFactorEmailService>();


// Identity cookie ayarlar�
builder.Services.ConfigureApplicationCookie(options =>
{
    options.Cookie.HttpOnly = true;
    options.Cookie.SecurePolicy = Microsoft.AspNetCore.Http.CookieSecurePolicy.Always;
    options.Cookie.SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Lax;
});

// Authentication ayarlar� � Identity'nin default cookie'si kullan�l�yor.
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
    options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
})
.AddJwtBearer("Jwt", options =>
{
    var jwtConfig = builder.Configuration.GetSection("JWT");
    options.TokenValidationParameters.ClockSkew = TimeSpan.Zero;
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



builder.Services.AddSingleton<IRateLimitConfiguration, RateLimitConfiguration>();

builder.Services.AddSingleton<GeoIPService>();

builder.Services.AddScoped<UserSecurityService>();

builder.Services.AddScoped<RolePermissionService>();

builder.Services.AddScoped<PageDiscoveryService>();


// Swagger (API dok�mantasyonu)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(options =>
{
    options.AddSecurityDefinition("Bearer", new Microsoft.OpenApi.Models.OpenApiSecurityScheme
    {
        Description = "JWT Authorization header using the Bearer scheme. �rne�in: \"Bearer {token}\"",
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

using (var scope = app.Services.CreateScope())
{
    var scopedProvider = scope.ServiceProvider;
    var pageDiscoveryService = scopedProvider.GetRequiredService<PageDiscoveryService>();
    var dbContext = scopedProvider.GetRequiredService<ApplicationDbContext>();

    var existingPages = dbContext.RolePermissions.Select(r => r.PagePath).Distinct().ToList();
    var allPages = pageDiscoveryService.GetAllPages().Distinct();

    foreach (var page in allPages)
    {
        if (!existingPages.Any(p => p.Equals(page, StringComparison.OrdinalIgnoreCase)))
        {
            dbContext.RolePermissions.Add(new RolePermission
            {
                RoleName = "Admin",
                PagePath = page,
                CanAccess = true
            });
        }
    }
    dbContext.SaveChanges();
}

app.UseIpRateLimiting();

// Production ortam� i�in hata y�netimi
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
});


app.UseExceptionHandler("/Error");
app.UseStatusCodePagesWithReExecute("/Error/{0}");


app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseResponseCaching();
app.UseRouting();
app.MapHealthChecks("/health");
app.UseCors("AllowAll");
app.UseAuthentication();
app.UseAuthorization();
app.UseIpRateLimiting();
app.UseSession();

// SignalR hub'�
app.MapHub<StatusHub>("/statusHub");

// Performans metrikleri middleware
app.UseMiddleware<PerformanceMetricsMiddleware>();
app.UseMiddleware<ActivityLoggingMiddleware>();
app.UseMiddleware<RolePermissionMiddleware>();
app.UseMiddleware<AutoDiscoverMiddleware>();




// Swagger middleware'leri
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "My API V1");
    });
}




app.Use(async (context, next) =>
{
    var path = context.Request.Path.ToString().ToLower();

    // ?? ROOT URL NORMAL�ZASYONU
    if (path == "/" || path == "/index.html" || path == "/Home" || path == "/home")
    {
        Console.WriteLine($"?? PATH D�ZELT�LD�: {path} ? /Home/Index");
        path = "/Home/Index"; // ?? Ana sayfay� /Home/Index olarak y�nlendir
        context.Request.Path = path;
    }

    await next();
});




// Seeding: Admin ve roller olu�turuluyor
using (var scope = app.Services.CreateScope())
{
    var services = scope.ServiceProvider;
    await DbInitializer.InitializeAsync(services);
}



// Routing: Areas ve default route
app.MapControllerRoute(
    name: "areas",
    pattern: "{area:exists}/{controller=Home}/{action=Index}/{id?}");
app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");


app.Run();
