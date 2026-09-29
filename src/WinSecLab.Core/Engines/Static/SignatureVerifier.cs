using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Security.Cryptography.Pkcs;
using System.Security.Cryptography.X509Certificates;
using WinSecLab.Core.Models;
using WinSecLab.Core.Util;

namespace WinSecLab.Core.Engines.Static;

/// <summary>§3.3 Digital Signature —— WinVerifyTrust 权威校验 + 签名链 / 时间戳提取。</summary>
public static class SignatureVerifier
{
    private static readonly Guid WINTRUST_ACTION_GENERIC_VERIFY_V2 =
        new("00AAC56B-CD44-11d0-8CC2-00C04FC295EE");

    private const uint WTD_UI_NONE = 2;
    private const uint WTD_REVOKE_NONE = 0;
    private const uint WTD_CHOICE_FILE = 1;
    private const uint WTD_STATEACTION_VERIFY = 1;
    private const uint WTD_STATEACTION_CLOSE = 2;
    private const uint WTD_SAFER_FLAG = 0x00000100;

    public static SignatureInfo Verify(string filePath)
    {
        var info = new SignatureInfo();

        if (!File.Exists(filePath))
        {
            info.Status = SignatureStatus.UnknownError;
            info.StatusText = "文件不存在";
            return info;
        }

        try
        {
            info.WinVerifyTrustResult = (long)RunWinVerifyTrust(filePath, out var hresult);
            info.Status = MapStatus((uint)info.WinVerifyTrustResult);
            info.StatusText = DescribeStatus(info.Status, (uint)info.WinVerifyTrustResult);

            if (info.Status is SignatureStatus.NotSigned)
                return info;
        }
        catch (DllNotFoundException)
        {
            info.Status = SignatureStatus.Unavailable;
            info.StatusText = "wintrust.dll 不可用（非 Windows 宿主）";
            return info;
        }
        catch (Exception ex)
        {
            info.Status = SignatureStatus.UnknownError;
            info.StatusText = $"校验异常：{ex.GetType().Name}";
        }

        FillCertificateDetails(filePath, info);
        return info;
    }

    private static uint RunWinVerifyTrust(string filePath, out int lastError)
    {
        var fileInfo = new NativeMethods.WINTRUST_FILE_INFO
        {
            cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>(),
            pcwszFilePath = filePath,
            hFile = IntPtr.Zero,
            pgKnownSubject = IntPtr.Zero,
        };

        var fileInfoPtr = Marshal.AllocHGlobal(Marshal.SizeOf<NativeMethods.WINTRUST_FILE_INFO>());
        try
        {
            Marshal.StructureToPtr(fileInfo, fileInfoPtr, false);

            var data = new NativeMethods.WINTRUST_DATA
            {
                cbStruct = (uint)Marshal.SizeOf<NativeMethods.WINTRUST_DATA>(),
                dwUIChoice = WTD_UI_NONE,
                fdwRevocationChecks = WTD_REVOKE_NONE,
                dwUnionChoice = WTD_CHOICE_FILE,
                pFile = fileInfoPtr,
                dwStateAction = WTD_STATEACTION_VERIFY,
                dwProvFlags = WTD_SAFER_FLAG,
            };

            var result = NativeMethods.WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref data);

            // 必须显式关闭状态，否则会泄漏句柄并可能阻塞后续校验
            var closeData = data;
            closeData.dwStateAction = WTD_STATEACTION_CLOSE;
            try
            {
                NativeMethods.WinVerifyTrust(IntPtr.Zero, WINTRUST_ACTION_GENERIC_VERIFY_V2, ref closeData);
            }
            catch
            {
                // 关闭失败不影响结论
            }

            lastError = Marshal.GetLastWin32Error();
            return result;
        }
        finally
        {
            Marshal.FreeHGlobal(fileInfoPtr);
        }
    }

    private static SignatureStatus MapStatus(uint result) => result switch
    {
        0 => SignatureStatus.Valid,
        0x800B0100 => SignatureStatus.NotSigned,          // TRUST_E_NOSIGNATURE
        0x800B0003 => SignatureStatus.NotSigned,          // TRUST_E_SUBJECT_FORM_UNKNOWN
        0x800B0004 => SignatureStatus.NotSigned,          // TRUST_E_PROVIDER_UNKNOWN
        0x800B0109 => SignatureStatus.ValidButUntrusted,  // CERT_E_UNTRUSTEDROOT
        0x800B010A => SignatureStatus.ValidButUntrusted,  // CERT_E_CHAINING
        0x800B0101 => SignatureStatus.Invalid,            // CERT_E_EXPIRED
        0x800B010C => SignatureStatus.Invalid,            // CERT_E_REVOKED
        0x800B0111 => SignatureStatus.Invalid,            // TRUST_E_EXPLICIT_DISTRUST
        0x80096010 => SignatureStatus.Invalid,            // TRUST_E_BAD_DIGEST （二进制已被篡改）
        0x800B010B => SignatureStatus.Invalid,            // TRUST_E_SUBJECT_NOT_TRUSTED
        0x800B0001 => SignatureStatus.Unavailable,        // TRUST_E_PROVIDER_UNKNOWN
        _ => SignatureStatus.Invalid,
    };

    private static string DescribeStatus(SignatureStatus status, uint result) => status switch
    {
        SignatureStatus.Valid => "签名有效且受信任",
        SignatureStatus.ValidButUntrusted => "签名有效，但证书链不受信任（0x800B0109/0x800B010A）",
        SignatureStatus.NotSigned => "未签名",
        SignatureStatus.Invalid when result == 0x80096010 => "签名无效 —— 摘要不匹配（文件在签名后被修改）",
        SignatureStatus.Invalid when result == 0x800B0101 => "证书已过期",
        SignatureStatus.Invalid when result == 0x800B010C => "证书已被吊销",
        SignatureStatus.Invalid when result == 0x800B0111 => "证书被显式不信任",
        SignatureStatus.Invalid => $"签名无效（0x{result:X8}）",
        SignatureStatus.Unavailable => "签名校验不可用",
        _ => $"未知状态（0x{result:X8}）",
    };

    private static void FillCertificateDetails(string filePath, SignatureInfo info)
    {
        // 1) 最简路径：取签名者证书
        try
        {
            using var cert = X509Certificate.CreateFromSignedFile(filePath);
            using var cert2 = new X509Certificate2(cert);
            info.SignerSubject = cert2.Subject;
            info.SignerIssuer = cert2.Issuer;
            info.SignerThumbprint = cert2.Thumbprint;
            info.NotBefore = cert2.NotBefore;
            info.NotAfter = cert2.NotAfter;

            info.ChainIssues = BuildChainIssues(cert2);
            if (info.ChainIssues.Count > 0 && info.Status == SignatureStatus.Valid)
            {
                info.Status = SignatureStatus.ValidButUntrusted;
                info.StatusText = "签名有效，但证书链存在问题";
            }
        }
        catch (CryptographicException)
        {
            // 未签名或证书无法读取，保留 WinVerifyTrust 结论
        }
        catch (Exception ex)
        {
            info.ChainIssues.Add($"读取签名者证书失败：{ex.Message}");
        }

        // 2) 深入路径：解析 PKCS#7 以取得时间戳与副署信息
        try
        {
            var pkcs7 = ExtractPkcs7(filePath);
            if (pkcs7 is not null)
            {
                var cms = new SignedCms();
                cms.Decode(pkcs7);
                foreach (var signer in cms.SignerInfos)
                {
                    var counter = signer.CounterSignerInfos;
                    if (counter.Count > 0)
                    {
                        info.IsTimestamped = true;
                        foreach (var cs in counter)
                        {
                            var tsCert = cs.Certificate;
                            if (tsCert is not null)
                            {
                                info.TimestampAuthority = ExtractCommonName(tsCert.Subject);
                                break;
                            }
                        }
                    }
                }

                if (cms.Certificates.Count > 1)
                {
                    foreach (var c in cms.Certificates)
                    {
                        if (c.Subject == info.SignerSubject) continue;
                        if (c.Subject.Contains("timestamp", StringComparison.OrdinalIgnoreCase) ||
                            c.Subject.Contains("TSA", StringComparison.OrdinalIgnoreCase))
                        {
                            info.IsTimestamped = true;
                            info.TimestampAuthority ??= ExtractCommonName(c.Subject);
                        }
                    }
                }
            }
        }
        catch
        {
            // 时间戳是附加信息，解析失败不影响主结论
        }
    }

    private static List<string> BuildChainIssues(X509Certificate2 cert)
    {
        var issues = new List<string>();
        try
        {
            using var chain = new X509Chain();
            chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
            chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;
            if (chain.Build(cert)) return issues;

            foreach (var element in chain.ChainElements)
            {
                foreach (var status in element.ChainElementStatus)
                {
                    var text = status.Status switch
                    {
                        X509ChainStatusFlags.UntrustedRoot => "根证书不在受信任存储中",
                        X509ChainStatusFlags.NotTimeValid => "证书已过期或尚未生效",
                        X509ChainStatusFlags.Revoked => "证书已被吊销",
                        X509ChainStatusFlags.NotSignatureValid => "证书链签名校验失败",
                        X509ChainStatusFlags.PartialChain => "证书链不完整",
                        X509ChainStatusFlags.NotValidForUsage => "证书用途不匹配",
                        _ => $"链状态：{status.Status}",
                    };
                    if (!issues.Contains(text)) issues.Add(text);
                }
            }
        }
        catch (Exception ex)
        {
            issues.Add($"证书链校验失败：{ex.Message}");
        }
        return issues;
    }

    /// <summary>从 PE 证书表（Data Directory 4）中抠出 PKCS#7 DER 字节。</summary>
    private static byte[]? ExtractPkcs7(string filePath)
    {
        using var fs = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
        using var reader = new BinaryReader(fs);
        if (fs.Length < 0x100) return null;
        if (reader.ReadUInt16() != 0x5A4D) return null; // MZ

        fs.Position = 0x3C;
        var peOffset = reader.ReadInt32();
        if (peOffset <= 0 || peOffset + 0x108 > fs.Length) return null;

        fs.Position = peOffset;
        if (reader.ReadUInt32() != 0x00004550) return null; // PE\0\0

        fs.Position = peOffset + 0x18;
        var magic = reader.ReadUInt16();
        var isPe32Plus = magic == 0x20B;

        // Data directory 起始：PE32+ 为 optional header + 0x70，PE32 为 +0x60
        var dataDirStart = peOffset + 0x18 + (isPe32Plus ? 0x70 : 0x60);
        // 索引 4 = Certificate Table
        var certEntry = dataDirStart + 4 * 8;
        if (certEntry + 8 > fs.Length) return null;

        fs.Position = certEntry;
        var certOffset = reader.ReadUInt32();
        var certSize = reader.ReadUInt32();
        if (certOffset == 0 || certSize == 0) return null;
        if (certOffset + certSize > fs.Length) return null;

        fs.Position = certOffset;
        var raw = reader.ReadBytes((int)Math.Min(certSize, 8 << 20));

        // WIN_CERTIFICATE 头 8 字节，之后是 DER。部分工具会填 8 字节对齐的填充，
        // 因此直接定位第一个 plausible 的 SEQUENCE (0x30 0x8x) 起始位置。
        for (var i = 0; i + 4 < raw.Length; i++)
        {
            if (raw[i] != 0x30) continue;
            var b1 = raw[i + 1];
            if (b1 == 0x80 || b1 == 0x81 || b1 == 0x82 || b1 == 0x83)
                return raw[i..];
        }
        return null;
    }

    private static string ExtractCommonName(string subject)
    {
        foreach (var part in subject.Split(','))
        {
            var t = part.Trim();
            if (t.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                return t[3..].Trim('"');
        }
        return subject;
    }
}
