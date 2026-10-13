using MtlsLab.Education;
using MtlsLab.Web.Components;
using Microsoft.AspNetCore.Components.Server.ProtectedBrowserStorage;
using Microsoft.AspNetCore.DataProtection;

var builder = WebApplication.CreateBuilder(args);
builder.WebHost.UseStaticWebAssets();
// A remote deployment must explicitly configure its own listener and web-tier protections.
if (string.IsNullOrEmpty(builder.Configuration["urls"])) builder.WebHost.UseUrls("http://127.0.0.1:5080");
builder.Services.AddRazorComponents().AddInteractiveServerComponents(options =>
{
    options.DisconnectedCircuitRetentionPeriod = TimeSpan.FromMinutes(2);
    options.DetailedErrors = builder.Environment.IsDevelopment();
});
builder.Services.AddSingleton<ContentCatalogue>(); // Immutable teaching material only.
builder.Services.AddDataProtection().UseEphemeralDataProtectionProvider();
builder.Services.AddScoped<ProtectedSessionStorage>();
var app = builder.Build();
if (!app.Environment.IsDevelopment()) app.UseExceptionHandler("/error");
app.Use(async (context, next) =>
{
    context.Response.Headers["X-Content-Type-Options"] = "nosniff";
    context.Response.Headers["Referrer-Policy"] = "no-referrer";
    context.Response.Headers["X-Frame-Options"] = "DENY";
    await next();
});
app.UseStaticFiles();
app.UseAntiforgery();
app.MapStaticAssets();
app.MapGet("/health", () => Results.Ok(new { status = "ok", laboratory = "Bouncy Castle TLS 1.3", version = "2.7.0" }));
app.MapRazorComponents<App>().AddInteractiveServerRenderMode();
app.Run();
