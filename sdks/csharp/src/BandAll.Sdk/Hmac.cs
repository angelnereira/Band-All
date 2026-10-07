// BandAll thin C# SDK: HMAC request signatures (blueprint §10).

using System.Security;
using System.Security.Cryptography;
using System.Text;

namespace BandAll;

/// <summary>A request to sign, with its canonical components.</summary>
public sealed record SignRequest(
    string Method, string Path, string Query, byte[] Body, long Timestamp, string Nonce);

/// <summary>HMAC-SHA256 request signatures.</summary>
public static class Hmac
{
    /// <summary>Default clock tolerance in seconds.</summary>
    public const long ClockToleranceSecs = 300;

    private static readonly UTF8Encoding Utf8 = new(false);

    /// <summary>Canonical string: METHOD\nPATH\nQUERY\nSHA256(body)\ntimestamp\nnonce.</summary>
    public static string Canonical(SignRequest req)
    {
        foreach (var part in new[] { req.Method, req.Path, req.Query, req.Nonce })
        {
            if (part.Contains('\n') || part.Contains('\r'))
                throw new ArgumentException("malformed field");
        }
        var bodyHash = SHA256.HashData(req.Body);
        return $"{req.Method.ToUpperInvariant()}\n{req.Path}\n{req.Query}\n" +
               $"{Convert.ToHexString(bodyHash).ToLowerInvariant()}\n{req.Timestamp}\n{req.Nonce}";
    }

    /// <summary>Signs the canonical string, returning <c>v1=&lt;hex&gt;</c>.</summary>
    public static string Sign(string keyHex, SignRequest req)
    {
        var key = Convert.FromHexString(keyHex);
        using var mac = new HMACSHA256(key);
        var digest = mac.ComputeHash(Utf8.GetBytes(Canonical(req)));
        return "v1=" + Convert.ToHexString(digest).ToLowerInvariant();
    }

    /// <summary>
    /// Verifies structure, clock tolerance and signature in constant time.
    /// Replay is the caller's responsibility (a store keyed by nonce).
    /// </summary>
    public static void VerifySignature(
        string keyHex, SignRequest req, string presented, long now, long clockToleranceSecs = ClockToleranceSecs)
    {
        if (Math.Abs(req.Timestamp - now) > clockToleranceSecs)
            throw new SecurityException("stale timestamp");
        var expected = Sign(keyHex, req);
        if (presented.Length != expected.Length ||
            !CryptographicOperations.FixedTimeEquals(Utf8.GetBytes(expected), Utf8.GetBytes(presented)))
        {
            throw new SecurityException("bad signature");
        }
    }
}