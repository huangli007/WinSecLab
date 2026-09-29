using System.Reflection;
using System.Reflection.Metadata;
using System.Reflection.PortableExecutable;
using WinSecLab.Core.Models;

namespace WinSecLab.Core.Engines.Static;

/// <summary>
/// §3.4 .NET 分析。用 System.Reflection.Metadata 读元数据表，
/// 得到程序集结构树（命名空间 → 类型 → 成员）与引用关系，供 UI 展示与混淆识别。
/// 实际 C# 源码级反编译交给 ILSpy / dnSpyEx 插件（§17），这里不重复造。
/// </summary>
public sealed class DotNetAnalyzer
{
    private const int MaxTypesPerNamespace = 400;
    private const int MaxMembersPerType = 300;
    private const int MaxMethodReferences = 3000;

    private static readonly string[] ObfuscatorMarkers =
    {
        "ConfusedByAttribute", "ConfuserEx", "ObfuscatedByGoliath", "ObfuscatedBy",
        "SmartAssembly", "Eazfuscator", "Dotfuscator", "Babel Obfuscator", "Agile.NET",
        ".NET Reactor", "Themida", ".NETGuard", "DeepSea", "MaxtoCode", "ILProtector",
        "Xenocode", "Sixxpack", "Rummage", "Spfuscator", "Dotnet IL Editor",
    };

    public DotNetAssemblyInfo Analyze(string filePath, PeImageInfo? peInfo = null)
    {
        var result = new DotNetAssemblyInfo();

        try
        {
            using var stream = new FileStream(filePath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite);
            using var reader = new PEReader(stream, PEStreamOptions.LeaveOpen);

            if (reader.PEHeaders.CorHeader is null)
            {
                result.IsDotNet = false;
                return result;
            }

            result.IsDotNet = true;
            result.RuntimeVersion = reader.PEHeaders.CorHeader.MajorRuntimeVersion +
                                    "." + reader.PEHeaders.CorHeader.MinorRuntimeVersion;
            result.IsReadyToRun = reader.PEHeaders.CorHeader.ManagedNativeHeaderDirectory.Size > 0;
            result.IsNativeAot = reader.PEHeaders.CorHeader.Flags.HasFlag(CorFlags.NativeEntryPoint);
            result.EntryPointToken = $"0x{reader.PEHeaders.CorHeader.EntryPointTokenOrRelativeVirtualAddress:X8}";
            result.IsManagedEntryPoint = reader.PEHeaders.CorHeader.EntryPointTokenOrRelativeVirtualAddress != 0;

            if (!reader.HasMetadata)
            {
                // NativeAOT / ReadyToRun 单文件可能没有可读的托管元数据表
                result.Decompilable = false;
                result.ObfuscationHints.Add("文件缺少可读托管元数据（NativeAOT 或受保护镜像）");
                return result;
            }

            var md = reader.GetMetadataReader();
            ReadAssemblyIdentity(md, result);
            ReadTargetFramework(md, result);
            ReadTypeTree(md, result);
            ReadReferences(md, result);
            ReadResources(md, result);
            ReadMethodReferences(md, result);
            DetectObfuscation(md, result, peInfo);
        }
        catch (BadImageFormatException)
        {
            result.IsDotNet = false;
        }
        catch (Exception ex)
        {
            result.IsDotNet = false;
            result.ObfuscationHints.Add($"读取托管元数据失败：{ex.GetType().Name}");
        }

        return result;
    }

    private static void ReadAssemblyIdentity(MetadataReader md, DotNetAssemblyInfo result)
    {
        var asm = md.GetAssemblyDefinition();
        result.AssemblyName = md.GetString(asm.Name);
        result.AssemblyVersion = asm.Version.ToString();
        result.ModuleName = md.GetString(md.GetModuleDefinition().Name);

        foreach (var handle in asm.GetCustomAttributes())
        {
            var attr = md.GetCustomAttribute(handle);
            var name = GetAttributeTypeName(md, attr);
            if (!string.IsNullOrEmpty(name)) result.CustomAttributes.Add(name);
        }
    }

    private static void ReadTargetFramework(MetadataReader md, DotNetAssemblyInfo result)
    {
        foreach (var handle in md.GetAssemblyDefinition().GetCustomAttributes())
        {
            var attr = md.GetCustomAttribute(handle);
            var name = GetAttributeTypeName(md, attr);
            if (name is not "TargetFrameworkAttribute" and not "System.Runtime.Versioning.TargetFrameworkAttribute")
                continue;

            try
            {
                var value = md.GetBlobReader(attr.Value);
                if (value.ReadUInt16() != 1) return;
                result.TargetFramework = value.ReadSerializedString();
            }
            catch
            {
                // 属性 blob 格式异常，忽略
            }
        }
    }

    private static void ReadTypeTree(MetadataReader md, DotNetAssemblyInfo result)
    {
        var namespaces = new Dictionary<string, DotNetNamespace>(StringComparer.Ordinal);

        foreach (var typeHandle in md.TypeDefinitions)
        {
            var type = md.GetTypeDefinition(typeHandle);

            var ns = md.GetString(type.Namespace);
            if (string.IsNullOrEmpty(ns)) ns = "<全局命名空间>";
            // 编译器生成的嵌套类型用 <...> 标记，归到独立分组避免淹没真实类型
            if (ns.StartsWith("<", StringComparison.Ordinal)) ns = "<编译器生成>";

            if (!namespaces.TryGetValue(ns, out var nsNode))
            {
                nsNode = new DotNetNamespace { Name = ns };
                namespaces[ns] = nsNode;
            }

            if (nsNode.Types.Count >= MaxTypesPerNamespace) continue;

            var attr = type.Attributes;
            var accessibility = (attr & TypeAttributes.VisibilityMask) switch
            {
                TypeAttributes.Public => "public",
                TypeAttributes.NestedPublic => "nested public",
                TypeAttributes.NestedPrivate => "nested private",
                TypeAttributes.NestedFamily => "nested protected",
                TypeAttributes.NestedAssembly => "nested internal",
                TypeAttributes.NestedFamORAssem => "nested protected internal",
                TypeAttributes.NestedFamANDAssem => "nested private protected",
                _ => "internal",
            };

            var typeName = md.GetString(type.Name);
            var rawNamespace = md.GetString(type.Namespace);

            var typeNode = new DotNetType
            {
                Name = typeName,
                FullName = string.IsNullOrEmpty(rawNamespace) ? typeName : $"{rawNamespace}.{typeName}",
                Accessibility = accessibility,
                IsInterface = (attr & TypeAttributes.Interface) != 0,
                IsEnum = attr.HasFlag(TypeAttributes.Sealed) && GetBaseTypeName(md, type) == "System.Enum",
                IsValueType = GetBaseTypeName(md, type) == "System.ValueType",
                IsDelegate = GetBaseTypeName(md, type) is "System.MulticastDelegate" or "System.Delegate",
                BaseType = GetBaseTypeName(md, type),
            };

            foreach (var ifaceHandle in type.GetInterfaceImplementations())
            {
                try
                {
                    var iface = md.GetInterfaceImplementation(ifaceHandle);
                    var name = ResolveEntityName(md, iface.Interface);
                    if (!string.IsNullOrEmpty(name)) typeNode.Interfaces.Add(name);
                }
                catch
                {
                    // 单条记录损坏不影响整体
                }
            }

            FillMembers(md, type, typeNode);
            nsNode.Types.Add(typeNode);
        }

        result.Namespaces = namespaces.Values
            .OrderBy(n => n.Name == "<全局命名空间>" ? 1 : n.Name == "<编译器生成>" ? 2 : 0)
            .ThenBy(n => n.Name, StringComparer.Ordinal)
            .ToList();
    }

    private static void FillMembers(MetadataReader md, TypeDefinition type, DotNetType typeNode)
    {
        var budget = MaxMembersPerType;

        foreach (var handle in type.GetMethods())
        {
            if (budget-- <= 0) break;
            try
            {
                var m = md.GetMethodDefinition(handle);
                typeNode.Methods.Add(new DotNetMember
                {
                    Name = md.GetString(m.Name),
                    Kind = "Method",
                    Accessibility = DescribeMethodAccess(m.Attributes),
                    Signature = $"{DescribeMethodAccess(m.Attributes)} {md.GetString(m.Name)}(...)",
                });
            }
            catch
            {
                // 忽略
            }
        }

        foreach (var handle in type.GetFields())
        {
            if (budget-- <= 0) break;
            try
            {
                var f = md.GetFieldDefinition(handle);
                typeNode.Fields.Add(new DotNetMember
                {
                    Name = md.GetString(f.Name),
                    Kind = "Field",
                    Accessibility = DescribeFieldAccess(f.Attributes),
                });
            }
            catch
            {
                // 忽略
            }
        }

        foreach (var handle in type.GetProperties())
        {
            if (budget-- <= 0) break;
            try
            {
                var p = md.GetPropertyDefinition(handle);
                typeNode.Properties.Add(new DotNetMember
                {
                    Name = md.GetString(p.Name),
                    Kind = "Property",
                });
            }
            catch
            {
                // 忽略
            }
        }

        foreach (var handle in type.GetEvents())
        {
            if (budget-- <= 0) break;
            try
            {
                var e = md.GetEventDefinition(handle);
                typeNode.Events.Add(new DotNetMember
                {
                    Name = md.GetString(e.Name),
                    Kind = "Event",
                });
            }
            catch
            {
                // 忽略
            }
        }
    }

    private static string DescribeMethodAccess(MethodAttributes a) => (a & MethodAttributes.MemberAccessMask) switch
    {
        MethodAttributes.Public => "public",
        MethodAttributes.Private => "private",
        MethodAttributes.Family => "protected",
        MethodAttributes.Assembly => "internal",
        MethodAttributes.FamORAssem => "protected internal",
        MethodAttributes.FamANDAssem => "private protected",
        _ => "private",
    };

    private static string DescribeFieldAccess(FieldAttributes a) => (a & FieldAttributes.FieldAccessMask) switch
    {
        FieldAttributes.Public => "public",
        FieldAttributes.Private => "private",
        FieldAttributes.Family => "protected",
        FieldAttributes.Assembly => "internal",
        FieldAttributes.FamORAssem => "protected internal",
        FieldAttributes.FamANDAssem => "private protected",
        _ => "private",
    };

    private static string? GetBaseTypeName(MetadataReader md, TypeDefinition type)
    {
        if (type.BaseType.IsNil) return null;
        return ResolveEntityName(md, type.BaseType);
    }

    private static string? ResolveEntityName(MetadataReader md, EntityHandle handle)
    {
        if (handle.IsNil) return null;
        try
        {
            switch (handle.Kind)
            {
                case HandleKind.TypeReference:
                {
                    var tr = md.GetTypeReference((TypeReferenceHandle)handle);
                    var ns = md.GetString(tr.Namespace);
                    var n = md.GetString(tr.Name);
                    return string.IsNullOrEmpty(ns) ? n : $"{ns}.{n}";
                }
                case HandleKind.TypeDefinition:
                {
                    var td = md.GetTypeDefinition((TypeDefinitionHandle)handle);
                    var ns = md.GetString(td.Namespace);
                    var n = md.GetString(td.Name);
                    return string.IsNullOrEmpty(ns) ? n : $"{ns}.{n}";
                }
                case HandleKind.TypeSpecification:
                    return "<generic>";
                default:
                    return null;
            }
        }
        catch
        {
            return null;
        }
    }

    private static void ReadReferences(MetadataReader md, DotNetAssemblyInfo result)
    {
        foreach (var handle in md.AssemblyReferences)
        {
            try
            {
                var ar = md.GetAssemblyReference(handle);
                var name = md.GetString(ar.Name);
                result.ReferencedAssemblies.Add($"{name} {ar.Version}");
            }
            catch
            {
                // 忽略
            }
        }
        result.ReferencedAssemblies.Sort(StringComparer.OrdinalIgnoreCase);
    }

    private static void ReadResources(MetadataReader md, DotNetAssemblyInfo result)
    {
        foreach (var handle in md.ManifestResources)
        {
            try
            {
                var r = md.GetManifestResource(handle);
                var name = md.GetString(r.Name);
                if (name.EndsWith(".resources", StringComparison.OrdinalIgnoreCase) && result.Resources.Count > 60)
                    continue;
                result.Resources.Add(name);
            }
            catch
            {
                // 忽略
            }
        }
        result.Resources.Sort(StringComparer.OrdinalIgnoreCase);
    }

    private static void ReadMethodReferences(MetadataReader md, DotNetAssemblyInfo result)
    {
        var count = 0;
        var seen = new HashSet<string>(StringComparer.Ordinal);
        foreach (var handle in md.MemberReferences)
        {
            if (count >= MaxMethodReferences) break;
            try
            {
                var mr = md.GetMemberReference(handle);
                if (mr.GetKind() != MemberReferenceKind.Method) continue;

                var parent = ResolveEntityName(md, mr.Parent) ?? "";
                var name = md.GetString(mr.Name);
                var key = $"{parent}.{name}";
                if (!seen.Add(key)) continue;

                var lastDot = parent.LastIndexOf('.');
                result.MethodReferences.Add(new DotNetMethodRef
                {
                    Namespace = lastDot > 0 ? parent[..lastDot] : parent,
                    TypeName = lastDot > 0 ? parent[(lastDot + 1)..] : parent,
                    MethodName = name,
                });
                count++;
            }
            catch
            {
                // 忽略
            }
        }
    }

    private static void DetectObfuscation(MetadataReader md, DotNetAssemblyInfo result, PeImageInfo? peInfo)
    {
        foreach (var handle in md.GetAssemblyDefinition().GetCustomAttributes())
        {
            try
            {
                var attr = md.GetCustomAttribute(handle);
                var name = GetAttributeTypeName(md, attr);
                if (string.IsNullOrEmpty(name)) continue;
                foreach (var marker in ObfuscatorMarkers)
                {
                    if (name.Contains(marker, StringComparison.OrdinalIgnoreCase))
                    {
                        result.UsesObfuscation = true;
                        result.ObfuscationHints.Add($"检出混淆器标记属性：{name}");
                    }
                }
            }
            catch
            {
                // 忽略
            }
        }

        // 命名熵：混淆器习惯把类型/方法名压成单字符或不可打印字符
        var shortNamedTypes = 0;
        var totalTypes = 0;
        var weirdNames = 0;

        foreach (var handle in md.TypeDefinitions)
        {
            try
            {
                var t = md.GetTypeDefinition(handle);
                var name = md.GetString(t.Name);
                if (name.StartsWith("<", StringComparison.Ordinal)) continue;
                totalTypes++;
                if (name.Length <= 2) shortNamedTypes++;
                if (name.Any(c => c < 0x20 || (c > 0x7E && char.IsControl(c)))) weirdNames++;
                if (name.Any(c => c is >= '\u4e00' and <= '\u9fff')) weirdNames++;
            }
            catch
            {
                // 忽略
            }
        }

        if (totalTypes > 20 && shortNamedTypes * 100 / totalTypes > 60)
        {
            result.UsesObfuscation = true;
            result.ObfuscationHints.Add($"{shortNamedTypes}/{totalTypes} 的类型名长度 ≤2 字符（符号名混淆特征）");
        }

        if (totalTypes > 10 && weirdNames * 100 / totalTypes > 30)
        {
            result.UsesObfuscation = true;
            result.ObfuscationHints.Add($"{weirdNames}/{totalTypes} 的类型名含非 ASCII / 控制字符（名称混淆特征）");
        }

        // 单文件打包：文件很大但元数据里只有极少数类型，真正的程序集在资源里
        if (peInfo is not null && peInfo.FileSize > 20L * 1024 * 1024 && totalTypes < 60)
        {
            result.IsSingleFileBundle = true;
            result.ObfuscationHints.Add("文件体积远大于元数据规模，疑似 .NET 单文件打包（bundle）");
        }

        var assemblyName = result.AssemblyName ?? "";
        if (assemblyName.Length > 0 && assemblyName.Length <= 3 && totalTypes > 50)
        {
            result.UsesObfuscation = true;
            result.ObfuscationHints.Add($"程序集名称为短随机串「{assemblyName}」");
        }

        if (result.ObfuscationHints.Count == 0)
            result.ObfuscationHints.Add("未发现明显混淆特征，可尝试用 ILSpy / dnSpyEx 直接反编译");

        result.Decompilable = !result.UsesObfuscation && !result.IsSingleFileBundle || result.Resources.Count < 5000;
        if (result.IsReadyToRun)
            result.ObfuscationHints.Add("存在 ReadyToRun 原生镜像头（ManagedNativeHeader），未签名时静态反编译仍可行");
    }

    private static string GetAttributeTypeName(MetadataReader md, CustomAttribute attr)
    {
        try
        {
            var ctor = attr.Constructor;
            if (ctor.Kind == HandleKind.MemberReference)
            {
                var mr = md.GetMemberReference((MemberReferenceHandle)ctor);
                return ResolveEntityName(md, mr.Parent);
            }
            if (ctor.Kind == HandleKind.MethodDefinition)
            {
                var mdef = md.GetMethodDefinition((MethodDefinitionHandle)ctor);
                return ResolveEntityName(md, mdef.GetDeclaringType());
            }
        }
        catch
        {
            // 忽略
        }
        return "";
    }
}
