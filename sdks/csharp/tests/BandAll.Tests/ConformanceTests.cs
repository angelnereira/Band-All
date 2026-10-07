// Conformance vectors: the same JSON every BandAll SDK must pass
// (`../../../conformance/vectors.json`).

using System.Security;
using System.Text.Json.Nodes;
using Xunit;

namespace BandAll.Tests;

public sealed class ConformanceTests
{
    /// <summary>
    /// Localiza los vectores compartidos subiendo desde el directorio del test
    /// hasta encontrarlos: el CWD con el que corre `dotnet test` varía según
    /// desde dónde se invoque, y depender de él rompe en CI.
    /// </summary>
    private static string FindVectors()
    {
        var dir = new DirectoryInfo(AppContext.BaseDirectory);
        while (dir != null)
        {
            var candidate = Path.Combine(dir.FullName, "conformance", "vectors.json");
            if (File.Exists(candidate)) return candidate;
            dir = dir.Parent;
        }
        throw new FileNotFoundException("no se encuentran los vectores compartidos");
    }

    private static readonly JsonObject vectors =
        JsonNode.Parse(File.ReadAllText(FindVectors()))!.AsObject();

    private static Jwks LoadJwks()
    {
        var keys = vectors["jwt"]!["jwks"]!["keys"]!.AsArray()
            .Select(k => new Jwk(
                (string)k!["kty"]!, (string)k["crv"]!, (string)k["kid"]!, (string)k["use"]!, (string)k["x"]!))
            .ToArray();
        return new Jwks(keys);
    }

    [Fact]
    public void ValidTokenVerifies()
    {
        var token = (string)vectors["jwt"]!["valid"]!;
        var claims = Jwt.Verify(
            LoadJwks(), token,
            (string)vectors["jwt"]!["issuer"]!, (string)vectors["jwt"]!["audience"]!,
            (long)vectors["now_secs"]!);
        Assert.Equal("alice", claims.Sub);
        Assert.Equal("acme", claims.Tenant);
        Assert.Equal(1, claims.Aal);
        Assert.Equal(["otp"], claims.Amr);
    }

    [Fact]
    public void TamperedTokenFails() =>
        Assert.Throws<SecurityException>(() => Jwt.Verify(
            LoadJwks(), (string)vectors["jwt"]!["tampered"]!,
            (string)vectors["jwt"]!["issuer"]!, (string)vectors["jwt"]!["audience"]!,
            (long)vectors["now_secs"]!));

    [Fact]
    public void WrongAudienceFails() =>
        Assert.Throws<SecurityException>(() => Jwt.Verify(
            LoadJwks(), (string)vectors["jwt"]!["wrong_aud"]!,
            (string)vectors["jwt"]!["issuer"]!, "my-app", (long)vectors["now_secs"]!));

    [Fact]
    public void ExpiredTokenFails() =>
        Assert.Throws<SecurityException>(() => Jwt.Verify(
            LoadJwks(), (string)vectors["jwt"]!["expired"]!,
            (string)vectors["jwt"]!["issuer"]!, (string)vectors["jwt"]!["audience"]!,
            (long)vectors["now_secs"]!));

    [Fact]
    public void NoneAlgorithmFails() =>
        Assert.Throws<SecurityException>(() => Jwt.Verify(
            LoadJwks(), (string)vectors["jwt"]!["none_alg"]!,
            (string)vectors["jwt"]!["issuer"]!, (string)vectors["jwt"]!["audience"]!,
            (long)vectors["now_secs"]!));

    [Fact]
    public void CanonicalStringMatchesVector()
    {
        var v = vectors["hmac"]!;
        var req = new SignRequest(
            (string)v["method"]!, (string)v["path"]!, (string)v["query"]!,
            System.Text.Encoding.UTF8.GetBytes((string)v["body"]!),
            (long)v["timestamp"]!, (string)v["nonce"]!);
        Assert.Equal((string)v["canonical"]!, Hmac.Canonical(req));
    }

    [Fact]
    public void SignatureMatchesVector()
    {
        var v = vectors["hmac"]!;
        var req = new SignRequest(
            (string)v["method"]!, (string)v["path"]!, (string)v["query"]!,
            System.Text.Encoding.UTF8.GetBytes((string)v["body"]!),
            (long)v["timestamp"]!, (string)v["nonce"]!);
        Assert.Equal((string)v["signature"]!, Hmac.Sign((string)v["key_hex"]!, req));
    }

    [Fact]
    public void SignatureVerifies()
    {
        var v = vectors["hmac"]!;
        var req = new SignRequest(
            (string)v["method"]!, (string)v["path"]!, (string)v["query"]!,
            System.Text.Encoding.UTF8.GetBytes((string)v["body"]!),
            (long)v["timestamp"]!, (string)v["nonce"]!);
        Hmac.VerifySignature((string)v["key_hex"]!, req, (string)v["signature"]!, (long)v["timestamp"]!);
    }

    [Fact]
    public void StaleSignatureFails()
    {
        var v = vectors["hmac"]!;
        var req = new SignRequest(
            (string)v["method"]!, (string)v["path"]!, (string)v["query"]!,
            System.Text.Encoding.UTF8.GetBytes((string)v["body"]!),
            (long)v["timestamp"]! + 301, (string)v["nonce"]!);
        Assert.Throws<SecurityException>(() => Hmac.VerifySignature(
            (string)v["key_hex"]!, req, (string)v["signature"]!, (long)v["timestamp"]!));
    }
}