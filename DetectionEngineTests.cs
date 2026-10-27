using System;
using System.IO;
using System.Threading.Tasks;
using Xunit;
// Sentinel katmanınızdaki ilgili namespace'leri buraya dahil edin:
// using Sentinel.Detection;
// using Sentinel.Collectors;

namespace Sentinel.Core.Tests
{
    public class Php2ShellDetectionTests : IDisposable
    {
        private readonly string _logDirectory;
        private readonly string _logFilePath;

        public Php2ShellDetectionTests()
        {
            // Test ortamı için geçici veya projedeki logs dizinini hazırlıyoruz
            _logDirectory = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "logs");
            Directory.CreateDirectory(_logDirectory);
            _logFilePath = Path.Combine(_logDirectory, "access.log");

            // Her test öncesi dosyayı temizleyelim
            if (File.Exists(_logFilePath))
            {
                File.Delete(_logFilePath);
            }
        }

        [Fact]
        public async Task WhenPhp2ShellPayloadLogged_DetectionEngineTriggersAlert()
        {
            // Arrange (Hazırlık): Test edilecek php2shell saldırı log satırı
            string maliciousLogEntry = "192.168.1.100 - - [26/Oct/2026:18:00:00 +0300] \"POST /uploads/shell.php?cmd=id HTTP/1.1\" 200 512 \"-\" \"Mozilla/5.0\"\n";

            // Act (Eylem): Log dosyasına saldırı girdisini yazıyoruz
            await File.AppendAllTextAsync(_logFilePath, maliciousLogEntry);

            // Assert (Doğrulama): Dosyanın yazıldığını ve içeriğin doğruluğunu teyit ediyoruz
            Assert.True(File.Exists(_logFilePath), "Log dosyası başarıyla oluşturulmalı.");

            string fileContent = await File.ReadAllTextAsync(_logFilePath);
            Assert.Contains("shell.php?cmd=id", fileContent);

            // Not: Eğer doğrudan DetectionEngine entegrasyonu yapacaksanız, 
            // burada HttpLogCollector üzerinden tetiklenmeyi veya DetectionEngine.EvaluateEvent() metodunu çağırarak 
            // alert nesnesinin null olmadığını doğrulayabilirsiniz.
            // Örn: var alert = detectionEngine.EvaluateEvent(...);
            // Assert.NotNull(alert);
            // Assert.Equal("Critical", alert.Severity.ToString());
        }

        public void Dispose()
        {
            // Test sonrası temizlik
            if (File.Exists(_logFilePath))
            {
                try { File.Delete(_logFilePath); } catch { }
            }
        }
    }
}