using Microsoft.Extensions.Configuration;
using Pr3.ConfigAndSecurity.Config;
using Xunit;

namespace Pr3.ConfigAndSecurity.Tests;

public sealed class ConfigurationPriorityTests
{
    [Fact]
    public void Приоритет_источников_работает_как_заявлено()
    {
        var file = new Dictionary<string, string?>
        {
            ["App:RateLimits:ReadPerMinute"] = "10"
        };

        var env = new Dictionary<string, string?>
        {
            ["App:RateLimits:ReadPerMinute"] = "20"
        };

        var args = new Dictionary<string, string?>
        {
            ["App:RateLimits:ReadPerMinute"] = "30"
        };

        var cfg = new ConfigurationBuilder()
            .AddInMemoryCollection(file)
            .AddInMemoryCollection(env)
            .AddInMemoryCollection(args)
            .Build();

        var opt = new AppOptions();
        cfg.GetSection("App").Bind(opt);

        Assert.Equal(30, opt.RateLimits.ReadPerMinute);
    }

    [Fact]
    public void Некорректные_настройки_даёт_ошибки_проверки()
    {
        var opt = new AppOptions
        {
            TrustedOrigins = Array.Empty<string>(),
            RateLimits = new RateLimitOptions { ReadPerMinute = 0, WritePerMinute = 0 }
        };

        var errors = AppOptionsValidator.Validate(opt);

        Assert.True(errors.Count >= 2);
        Assert.Contains(errors, e => e.Contains("доверенных", StringComparison.OrdinalIgnoreCase));
    }
}
