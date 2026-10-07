// BandAll thin C# SDK: offline JWT (EdDSA) verification and HMAC request
// signatures (H6). Same surface as the TS/Python/Go SDKs, and the same shared
// conformance vectors (`../../conformance/vectors.json`).

using System.Security;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;

namespace BandAll;

/// <summary>Public Ed25519 key as served in the JWKS document.</summary>
public sealed record Jwk(string Kty, string Crv, string Kid, string Use, string X);

/// <summary>JWKS document (`/.well-known/jwks.json`).</summary>
public sealed record Jwks(Jwk[] Keys);

/// <summary>Access-token claims a relying service may read after verification.</summary>
public sealed record Claims(
    string Iss, string Aud, string Sub, string Tenant, string Sid,
    string[] Amr, int Aal, string Jti, long Iat, long Exp);

/// <summary>Strict access-token verification against the JWKS.</summary>
public static class Jwt
{
    /// <summary>Clock skew tolerated for <c>exp</c>.</summary>
    public const long LeewaySecs = 60;

    private static readonly UTF8Encoding Utf8 = new(false);

    private static byte[] B64u(string segment)
    {
        // Base64URL sin padding -> Base64 estándar con padding.
        var padded = segment + new string('=', (4 - segment.Length % 4) % 4);
        return Convert.FromBase64String(padded.Replace('-', '+').Replace('_', '/'));
    }

    /// <summary>Verifies a BandAll access token strictly.</summary>
    /// <remarks>
    /// Fixed <c>EdDSA</c> algorithm, known <c>kid</c>, Ed25519 signature, then
    /// <c>iss</c>/<c>aud</c>/<c>exp</c>. Throws <see cref="SecurityException"/>
    /// on any failure, with no internal detail.
    /// </remarks>
    public static Claims Verify(Jwks jwks, string token, string issuer, string audience, long now)
    {
        var parts = token.Split('.');
        if (parts.Length != 3) throw new SecurityException("malformed token");

        var header = JsonNode.Parse(B64u(parts[0])) as JsonObject
            ?? throw new SecurityException("malformed header");
        string alg = (string?)header["alg"] ?? "";
        string kid = (string?)header["kid"] ?? "";
        if (alg != "EdDSA" || kid.Length == 0) throw new SecurityException("unexpected algorithm");

        var key = jwks.Keys.FirstOrDefault(k => k.Kid == kid && k.Crv == "Ed25519")
            ?? throw new SecurityException("unknown key id");
        var rawX = B64u(key.X);
        if (rawX.Length != 32) throw new SecurityException("invalid public key");

        var sig = B64u(parts[2]);
        if (sig.Length != 64) throw new SecurityException("invalid signature");

        if (!VerifyEd25519(rawX, Utf8.GetBytes($"{parts[0]}.{parts[1]}"), sig))
            throw new SecurityException("bad signature");

        var claimsNode = JsonNode.Parse(B64u(parts[1])) as JsonObject
            ?? throw new SecurityException("malformed claims");
        var claims = new Claims(
            (string?)claimsNode["iss"] ?? "", (string?)claimsNode["aud"] ?? "",
            (string?)claimsNode["sub"] ?? "", (string?)claimsNode["tenant"] ?? "",
            (string?)claimsNode["sid"] ?? "",
            ((JsonArray?)claimsNode["amr"])?.Select(x => (string?)x ?? "").ToArray() ?? [],
            (int?)claimsNode["aal"] ?? 0, (string?)claimsNode["jti"] ?? "",
            (long?)claimsNode["iat"] ?? 0, (long?)claimsNode["exp"] ?? 0);
        if (claims.Iss != issuer || claims.Aud != audience)
            throw new SecurityException("issuer or audience mismatch");
        if (claims.Exp < now - LeewaySecs) throw new SecurityException("token expired");
        return claims;
    }

    /// <summary>
    /// Ed25519 signature verification. .NET 8's BCL has no Ed25519, so this
    /// rides on BouncyCastle (NuGet <c>BouncyCastle.Cryptography</c>), the same
    /// way the Python SDK rides on <c>cryptography</c>. Only verification is
    /// implemented: this SDK never signs.
    /// </summary>
    private static bool VerifyEd25519(byte[] publicKey, byte[] message, byte[] signature)
    {
        try
        {
            var signer = new Org.BouncyCastle.Crypto.Signers.Ed25519Signer();
            var pub = new Org.BouncyCastle.Crypto.Parameters.Ed25519PublicKeyParameters(publicKey, 0);
            signer.Init(false, pub);
            signer.BlockUpdate(message, 0, message.Length);
            return signer.VerifySignature(signature);
        }
        catch
        {
            return false;
        }
    }
}