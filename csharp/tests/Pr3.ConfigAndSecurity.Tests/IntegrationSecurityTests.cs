using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Pr3.ConfigAndSecurity.Tests;

public sealed class IntegrationSecurityTests
{
    [Fact]
    public async Task Доверенный_источник_получает_разрешающий_заголовок()
    {
        var factory = CreateFactory(trustedOrigin: "http://localhost:5173", readLimit: 100, writeLimit: 100);
        var client = factory.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/items");
        request.Headers.TryAddWithoutValidation("Origin", "http://localhost:5173");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.True(response.Headers.TryGetValues("Access-Control-Allow-Origin", out var values));
        Assert.Contains("http://localhost:5173", values);
    }

    [Fact]
    public async Task Недоверенный_источник_не_получает_разрешающий_заголовок()
    {
        var factory = CreateFactory(trustedOrigin: "http://localhost:5173", readLimit: 100, writeLimit: 100);
        var client = factory.CreateClient();

        var request = new HttpRequestMessage(HttpMethod.Get, "/api/items");
        request.Headers.TryAddWithoutValidation("Origin", "http://evil.local");

        var response = await client.SendAsync(request);

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Fact]
    public async Task Ограничитель_частоты_возвращает_429()
    {
        // В шаблоне лимиты читаются из appsettings/env/args с явным приоритетом.
        // Для интеграционного теста проверяем сам факт наличия ограничения (а не подмену лимита),
        // поэтому превышаем дефолтный лимит из appsettings.json.
        var factory = CreateFactory(trustedOrigin: "http://localhost:5173", readLimit: 60, writeLimit: 20);
        var client = factory.CreateClient();

        async Task<HttpStatusCode> Call()
        {
            var request = new HttpRequestMessage(HttpMethod.Get, "/api/items");
            request.Headers.TryAddWithoutValidation("Origin", "http://localhost:5173");
            var resp = await client.SendAsync(request);
            return resp.StatusCode;
        }

        HttpStatusCode last = HttpStatusCode.OK;
        for (var i = 0; i < 61; i++)
            last = await Call();

        Assert.Equal((HttpStatusCode)429, last);
    }

    [Fact]
    public async Task Защитные_заголовки_присутствуют()
    {
        var factory = CreateFactory(trustedOrigin: "http://localhost:5173", readLimit: 100, writeLimit: 100);
        var client = factory.CreateClient();

        var response = await client.GetAsync("/api/items");

        Assert.True(response.Headers.Contains("X-Content-Type-Options"));
        Assert.True(response.Headers.Contains("X-Frame-Options"));
        Assert.True(response.Headers.Contains("Cache-Control"));
    }

    private static WebApplicationFactory<Program> CreateFactory(string trustedOrigin, int readLimit, int writeLimit)
    {
        return new WebApplicationFactory<Program>()
            .WithWebHostBuilder(builder =>
            {
                builder.ConfigureAppConfiguration((ctx, cfg) =>
                {
                    cfg.Sources.Clear();

                    var settings = new Dictionary<string, string?>
                    {
                        ["App:Mode"] = "Учебный",
                        ["App:TrustedOrigins:0"] = trustedOrigin,
                        ["App:RateLimits:ReadPerMinute"] = readLimit.ToString(),
                        ["App:RateLimits:WritePerMinute"] = writeLimit.ToString()
                    };

                    cfg.AddInMemoryCollection(settings);
                });
            });
    }
}
