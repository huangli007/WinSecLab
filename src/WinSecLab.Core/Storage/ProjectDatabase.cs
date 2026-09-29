using Microsoft.Data.Sqlite;
using WinSecLab.Core.Models;
using WinSecLab.Core.Serialization;

namespace WinSecLab.Core.Storage;

/// <summary>
/// 每个项目一个 SQLite 库（§16 Database / MVP 阶段）。
/// 写路径统一走 JSON 列 + 少量检索列，schema 演进时不需要迁移。
/// </summary>
public sealed class ProjectDatabase
{
    private readonly string _connectionString;

    public string DatabasePath { get; }
    public ProjectLayout Layout { get; }

    public ProjectDatabase(ProjectLayout layout)
    {
        Layout = layout;
        Directory.CreateDirectory(layout.Root);
        DatabasePath = layout.Database;
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = DatabasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            ForeignKeys = true,
        }.ToString();
    }

    public ProjectDatabase(string databasePath)
    {
        DatabasePath = databasePath;
        Layout = new ProjectLayout(Path.GetDirectoryName(databasePath) ?? ".");
        _connectionString = new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = SqliteOpenMode.ReadWriteCreate,
            Cache = SqliteCacheMode.Shared,
            Pooling = true,
            ForeignKeys = true,
        }.ToString();
    }

    private readonly object _schemaLock = new();
    private bool _schemaReady;

    private SqliteConnection Open()
    {
        var conn = new SqliteConnection(_connectionString);
        conn.Open();
        using var pragma = conn.CreateCommand();
        pragma.CommandText = "PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL; PRAGMA busy_timeout=8000;";
        pragma.ExecuteNonQuery();

        // 建表改成"首次真正用到库时自动完成"。
        // 要求每个调用方记得先 Initialize() 太容易漏（漏了就会在 SaveProject 上炸），
        // 而 DDL 全是 IF NOT EXISTS，重复执行的代价可以忽略。
        if (!_schemaReady)
        {
            lock (_schemaLock)
            {
                if (!_schemaReady)
                {
                    using var cmd = conn.CreateCommand();
                    cmd.CommandText = Schema;
                    cmd.ExecuteNonQuery();
                    _schemaReady = true;
                }
            }
        }

        return conn;
    }

    private const string Schema = """
        CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
        CREATE TABLE IF NOT EXISTS project (id TEXT PRIMARY KEY, name TEXT, updated_at TEXT, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions (id TEXT PRIMARY KEY, started_at TEXT, phase INTEGER, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS pe_images (path TEXT PRIMARY KEY, sha256 TEXT, is_dotnet INTEGER, runtime INTEGER, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS dotnet_assemblies (path TEXT PRIMARY KEY, assembly TEXT, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS dependencies (resolved_path TEXT PRIMARY KEY, name TEXT, is_present INTEGER, is_user_writable INTEGER, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS strings (id INTEGER PRIMARY KEY AUTOINCREMENT, offset INTEGER, section TEXT, is_unicode INTEGER, category TEXT, value TEXT);
        CREATE TABLE IF NOT EXISTS evidence (id TEXT PRIMARY KEY, kind INTEGER, title TEXT, source TEXT, target TEXT, timestamp TEXT, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, timestamp TEXT, type INTEGER, pid INTEGER, process_name TEXT, target TEXT, is_target_tree INTEGER, is_suspicious INTEGER, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS connections (id TEXT PRIMARY KEY, session_id TEXT, remote TEXT, remote_port INTEGER, pid INTEGER, process_name TEXT, domain TEXT, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS dns_observations (id INTEGER PRIMARY KEY AUTOINCREMENT, host TEXT, addresses TEXT, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS http_exchanges (id TEXT PRIMARY KEY, session_id TEXT, timestamp TEXT, method TEXT, host TEXT, path TEXT, status INTEGER, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS yara_matches (id INTEGER PRIMARY KEY AUTOINCREMENT, rule_name TEXT, file_path TEXT, severity TEXT, source TEXT, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, rule_id TEXT, severity INTEGER, confidence INTEGER, status INTEGER, category TEXT, title TEXT, timestamp TEXT, json TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, format TEXT, path TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS artifacts (id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, kind TEXT, name TEXT, path TEXT, size INTEGER, created_at TEXT);
        CREATE TABLE IF NOT EXISTS notes (id INTEGER PRIMARY KEY AUTOINCREMENT, created_at TEXT, author TEXT, body TEXT);

        CREATE INDEX IF NOT EXISTS ix_evidence_kind ON evidence(kind);
        CREATE INDEX IF NOT EXISTS ix_events_session ON events(session_id, timestamp);
        CREATE INDEX IF NOT EXISTS ix_events_type ON events(type);
        CREATE INDEX IF NOT EXISTS ix_events_pid ON events(pid);
        CREATE INDEX IF NOT EXISTS ix_findings_sev ON findings(severity);
        CREATE INDEX IF NOT EXISTS ix_conn_remote ON connections(remote);
        CREATE INDEX IF NOT EXISTS ix_http_host ON http_exchanges(host);
        """;

    /// <summary>
    /// 归还本库占用的连接池连接。
    /// 连接池会持有数据库文件句柄，导致项目目录删不掉（"正被另一进程使用"）。
    /// 删除项目目录前必须先调它 —— 测试与 UI 的"删除项目"功能都要遵守。
    /// </summary>
    public static void ReleasePools() => Microsoft.Data.Sqlite.SqliteConnection.ClearAllPools();

    public void Initialize()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = Schema;
        cmd.ExecuteNonQuery();
    }

    // ---------------------------------------------------------------- meta

    public void SetMeta(string key, string value)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO meta(key,value) VALUES($k,$v) ON CONFLICT(key) DO UPDATE SET value=$v;";
        cmd.Parameters.AddWithValue("$k", key);
        cmd.Parameters.AddWithValue("$v", value);
        cmd.ExecuteNonQuery();
    }

    public string? GetMeta(string key)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT value FROM meta WHERE key=$k;";
        cmd.Parameters.AddWithValue("$k", key);
        return cmd.ExecuteScalar() as string;
    }

    // ------------------------------------------------------------- project

    public void SaveProject(TestProject project)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO project(id,name,updated_at,json) VALUES($id,$name,$upd,$json)
            ON CONFLICT(id) DO UPDATE SET name=$name, updated_at=$upd, json=$json;
            """;
        cmd.Parameters.AddWithValue("$id", project.Id);
        cmd.Parameters.AddWithValue("$name", project.Name);
        cmd.Parameters.AddWithValue("$upd", project.UpdatedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$json", WslJson.Serialize(project));
        cmd.ExecuteNonQuery();
    }

    public TestProject? GetProject(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM project WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<TestProject>(json) : null;
    }

    /// <summary>
    /// 读取本库中的项目（一个项目一个库，因此取最新一条即可）。
    /// 供工作区服务在只知道目录、不知道项目编号时打开项目 —— 目录名里的编号是可读的，
    /// 但用户可能手工改过目录名，不能依赖它。
    /// </summary>
    public TestProject? GetPrimaryProject()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM project ORDER BY rowid DESC LIMIT 1;";
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<TestProject>(json) : null;
    }

    public TestProject? GetFirstProject()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM project ORDER BY updated_at DESC LIMIT 1;";
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<TestProject>(json) : null;
    }

    // ------------------------------------------------------------ sessions

    public void SaveSession(AnalysisSession session)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO sessions(id,started_at,phase,json) VALUES($id,$st,$ph,$json)
            ON CONFLICT(id) DO UPDATE SET phase=$ph, json=$json;
            """;
        cmd.Parameters.AddWithValue("$id", session.Id);
        cmd.Parameters.AddWithValue("$st", session.StartedAt.ToString("O"));
        cmd.Parameters.AddWithValue("$ph", (int)session.Phase);
        cmd.Parameters.AddWithValue("$json", WslJson.Serialize(session));
        cmd.ExecuteNonQuery();
    }

    public List<AnalysisSession> GetSessions(int limit = 50)
    {
        var list = new List<AnalysisSession>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM sessions ORDER BY started_at DESC LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var s = WslJson.Deserialize<AnalysisSession>(reader.GetString(0));
            if (s is not null) list.Add(s);
        }
        return list;
    }

    // ------------------------------------------------------------- static

    public void SavePeImage(PeImageInfo pe)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO pe_images(path,sha256,is_dotnet,runtime,json) VALUES($p,$s,$d,$r,$json)
            ON CONFLICT(path) DO UPDATE SET sha256=$s, is_dotnet=$d, runtime=$r, json=$json;
            """;
        cmd.Parameters.AddWithValue("$p", pe.FilePath);
        cmd.Parameters.AddWithValue("$s", pe.Sha256);
        cmd.Parameters.AddWithValue("$d", pe.IsDotNet ? 1 : 0);
        cmd.Parameters.AddWithValue("$r", (int)DetectRuntime(pe));
        cmd.Parameters.AddWithValue("$json", WslJson.Serialize(pe));
        cmd.ExecuteNonQuery();
    }

    private static AppRuntimeKind DetectRuntime(PeImageInfo pe) =>
        pe.IsDotNet ? AppRuntimeKind.DotNet : AppRuntimeKind.NativeCpp;

    public PeImageInfo? GetPeImage(string path)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM pe_images WHERE path=$p;";
        cmd.Parameters.AddWithValue("$p", path);
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<PeImageInfo>(json) : null;
    }

    public PeImageInfo? GetPrimaryPeImage()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM pe_images ORDER BY rowid LIMIT 1;";
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<PeImageInfo>(json) : null;
    }

    public List<PeImageInfo> GetPeImages()
    {
        var list = new List<PeImageInfo>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM pe_images ORDER BY rowid;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var pe = WslJson.Deserialize<PeImageInfo>(reader.GetString(0));
            if (pe is not null) list.Add(pe);
        }
        return list;
    }

    public void SaveDotNet(string path, DotNetAssemblyInfo info)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            INSERT INTO dotnet_assemblies(path,assembly,json) VALUES($p,$a,$json)
            ON CONFLICT(path) DO UPDATE SET assembly=$a, json=$json;
            """;
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$a", info.AssemblyName ?? "");
        cmd.Parameters.AddWithValue("$json", WslJson.Serialize(info));
        cmd.ExecuteNonQuery();
    }

    public DotNetAssemblyInfo? GetDotNet(string path)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM dotnet_assemblies WHERE path=$p;";
        cmd.Parameters.AddWithValue("$p", path);
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<DotNetAssemblyInfo>(json) : null;
    }

    public DotNetAssemblyInfo? GetFirstDotNet()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM dotnet_assemblies ORDER BY rowid LIMIT 1;";
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<DotNetAssemblyInfo>(json) : null;
    }

    public void SaveDependencies(IEnumerable<DependencyInfo> deps)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var d in deps)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO dependencies(resolved_path,name,is_present,is_user_writable,json) VALUES($p,$n,$pre,$uw,$json)
                ON CONFLICT(resolved_path) DO UPDATE SET name=$n, is_present=$pre, is_user_writable=$uw, json=$json;
                """;
            cmd.Parameters.AddWithValue("$p", d.ResolvedPath ?? d.Name);
            cmd.Parameters.AddWithValue("$n", d.Name);
            cmd.Parameters.AddWithValue("$pre", d.IsPresent ? 1 : 0);
            cmd.Parameters.AddWithValue("$uw", d.IsUserWritableLocation ? 1 : 0);
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(d));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<DependencyInfo> GetDependencies()
    {
        var list = new List<DependencyInfo>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM dependencies ORDER BY name;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var d = WslJson.Deserialize<DependencyInfo>(reader.GetString(0));
            if (d is not null) list.Add(d);
        }
        return list;
    }

    public void SaveStrings(IEnumerable<StringHit> hits)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        using (var del = conn.CreateCommand())
        {
            del.Transaction = tx;
            del.CommandText = "DELETE FROM strings;";
            del.ExecuteNonQuery();
        }
        foreach (var h in hits)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO strings(offset,section,is_unicode,category,value) VALUES($o,$s,$u,$c,$v);";
            cmd.Parameters.AddWithValue("$o", h.Offset);
            cmd.Parameters.AddWithValue("$s", h.Section);
            cmd.Parameters.AddWithValue("$u", h.IsUnicode ? 1 : 0);
            cmd.Parameters.AddWithValue("$c", h.Category);
            cmd.Parameters.AddWithValue("$v", h.Value);
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<StringHit> GetStrings(int limit = 5000)
    {
        var list = new List<StringHit>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT offset,section,is_unicode,category,value FROM strings LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            list.Add(new StringHit
            {
                Offset = reader.GetInt64(0),
                Section = reader.GetString(1),
                IsUnicode = reader.GetInt32(2) == 1,
                Category = reader.GetString(3),
                Value = reader.GetString(4),
            });
        }
        return list;
    }

    // ----------------------------------------------------------- evidence

    public void SaveEvidence(Evidence evidence)
    {
        SaveEvidence(new[] { evidence });
    }

    public void SaveEvidence(IEnumerable<Evidence> items)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var e in items)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO evidence(id,kind,title,source,target,timestamp,json) VALUES($id,$k,$t,$s,$tg,$ts,$json)
                ON CONFLICT(id) DO UPDATE SET kind=$k, title=$t, source=$s, target=$tg, json=$json;
                """;
            cmd.Parameters.AddWithValue("$id", e.Id);
            cmd.Parameters.AddWithValue("$k", (int)e.Kind);
            cmd.Parameters.AddWithValue("$t", e.Title);
            cmd.Parameters.AddWithValue("$s", e.Source);
            cmd.Parameters.AddWithValue("$tg", (object?)e.Target ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$ts", e.Timestamp.ToString("O"));
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(e));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<Evidence> GetEvidence(EvidenceKind? kind = null, string? search = null, int limit = 2000)
    {
        var list = new List<Evidence>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (kind is not null)
        {
            where.Add("kind=$k");
            cmd.Parameters.AddWithValue("$k", (int)kind.Value);
        }
        if (!string.IsNullOrWhiteSpace(search))
        {
            where.Add("(title LIKE $q OR target LIKE $q OR source LIKE $q)");
            cmd.Parameters.AddWithValue("$q", $"%{search}%");
        }
        cmd.CommandText = "SELECT json FROM evidence " +
                          (where.Count > 0 ? "WHERE " + string.Join(" AND ", where) + " " : "") +
                          "ORDER BY timestamp DESC LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var e = WslJson.Deserialize<Evidence>(reader.GetString(0));
            if (e is not null) list.Add(e);
        }
        return list;
    }

    public Evidence? GetEvidenceById(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM evidence WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<Evidence>(json) : null;
    }

    public int CountEvidence()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM evidence;";
        return Convert.ToInt32(cmd.ExecuteScalar() ?? 0);
    }

    // ------------------------------------------------------------- events

    public void SaveEvents(IEnumerable<MonitorEvent> events)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var e in events)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO events(session_id,timestamp,type,pid,process_name,target,is_target_tree,is_suspicious,json)
                VALUES($sid,$ts,$ty,$pid,$pn,$tg,$tt,$sp,$json);
                """;
            cmd.Parameters.AddWithValue("$sid", e.SessionId);
            cmd.Parameters.AddWithValue("$ts", e.Timestamp.ToString("O"));
            cmd.Parameters.AddWithValue("$ty", (int)e.Type);
            cmd.Parameters.AddWithValue("$pid", e.ProcessId);
            cmd.Parameters.AddWithValue("$pn", e.ProcessName);
            cmd.Parameters.AddWithValue("$tg", e.Target);
            cmd.Parameters.AddWithValue("$tt", e.IsFromTargetTree ? 1 : 0);
            cmd.Parameters.AddWithValue("$sp", e.IsSuspicious ? 1 : 0);
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(e));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<MonitorEvent> GetEvents(string? sessionId = null, MonitorEventType? type = null,
        bool suspiciousOnly = false, string? search = null, int limit = 5000)
    {
        var list = new List<MonitorEvent>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            where.Add("session_id=$sid");
            cmd.Parameters.AddWithValue("$sid", sessionId);
        }
        if (type is not null)
        {
            where.Add("type=$ty");
            cmd.Parameters.AddWithValue("$ty", (int)type.Value);
        }
        if (suspiciousOnly) where.Add("is_suspicious=1");
        if (!string.IsNullOrWhiteSpace(search))
        {
            where.Add("(target LIKE $q OR process_name LIKE $q OR detail LIKE $q)");
            cmd.Parameters.AddWithValue("$q", $"%{search}%");
        }
        cmd.CommandText = "SELECT json FROM events " +
                          (where.Count > 0 ? "WHERE " + string.Join(" AND ", where) + " " : "") +
                          "ORDER BY seq DESC LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var e = WslJson.Deserialize<MonitorEvent>(reader.GetString(0));
            if (e is not null) list.Add(e);
        }
        list.Reverse();
        return list;
    }

    public int CountEvents(bool suspiciousOnly = false)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = suspiciousOnly ? "SELECT COUNT(*) FROM events WHERE is_suspicious=1;" : "SELECT COUNT(*) FROM events;";
        return Convert.ToInt32(cmd.ExecuteScalar() ?? 0);
    }

    // -------------------------------------------------------- connections

    public void SaveConnections(IEnumerable<NetworkConnection> connections)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var c in connections)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO connections(id,session_id,remote,remote_port,pid,process_name,domain,json)
                VALUES($id,$sid,$r,$rp,$pid,$pn,$d,$json)
                ON CONFLICT(id) DO UPDATE SET remote=$r, remote_port=$rp, pid=$pid, process_name=$pn, domain=$d, json=$json;
                """;
            cmd.Parameters.AddWithValue("$id", c.Id);
            cmd.Parameters.AddWithValue("$sid", c.SessionId);
            cmd.Parameters.AddWithValue("$r", c.RemoteAddress);
            cmd.Parameters.AddWithValue("$rp", c.RemotePort);
            cmd.Parameters.AddWithValue("$pid", c.ProcessId);
            cmd.Parameters.AddWithValue("$pn", c.ProcessName);
            cmd.Parameters.AddWithValue("$d", (object?)c.Domain ?? DBNull.Value);
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(c));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<NetworkConnection> GetConnections(string? sessionId = null, string? search = null, int limit = 3000)
    {
        var list = new List<NetworkConnection>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            where.Add("session_id=$sid");
            cmd.Parameters.AddWithValue("$sid", sessionId);
        }
        if (!string.IsNullOrWhiteSpace(search))
        {
            where.Add("(remote LIKE $q OR domain LIKE $q OR process_name LIKE $q)");
            cmd.Parameters.AddWithValue("$q", $"%{search}%");
        }
        cmd.CommandText = "SELECT json FROM connections " +
                          (where.Count > 0 ? "WHERE " + string.Join(" AND ", where) + " " : "") +
                          "ORDER BY last_seen DESC LIMIT $n;";
        // 用 json 里的 LastSeen 排序不可行，改为 rowid
        cmd.CommandText = cmd.CommandText.Replace("last_seen", "rowid");
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var c = WslJson.Deserialize<NetworkConnection>(reader.GetString(0));
            if (c is not null) list.Add(c);
        }
        return list;
    }

    public void SaveDnsObservations(IEnumerable<DnsObservation> items)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var d in items)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO dns_observations(host,addresses,json) VALUES($h,$a,$json);";
            cmd.Parameters.AddWithValue("$h", d.HostName);
            cmd.Parameters.AddWithValue("$a", string.Join(";", d.Addresses));
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(d));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<DnsObservation> GetDnsObservations(int limit = 2000)
    {
        var list = new List<DnsObservation>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM dns_observations ORDER BY id DESC LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var d = WslJson.Deserialize<DnsObservation>(reader.GetString(0));
            if (d is not null) list.Add(d);
        }
        return list;
    }

    // ----------------------------------------------------- http exchange

    public void SaveHttpExchanges(IEnumerable<HttpExchange> items)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var x in items)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO http_exchanges(id,session_id,timestamp,method,host,path,status,json)
                VALUES($id,$sid,$ts,$m,$h,$p,$st,$json)
                ON CONFLICT(id) DO UPDATE SET status=$st, json=$json;
                """;
            cmd.Parameters.AddWithValue("$id", x.Id);
            cmd.Parameters.AddWithValue("$sid", x.SessionId);
            cmd.Parameters.AddWithValue("$ts", x.Timestamp.ToString("O"));
            cmd.Parameters.AddWithValue("$m", x.Method);
            cmd.Parameters.AddWithValue("$h", x.Host);
            cmd.Parameters.AddWithValue("$p", x.Path);
            cmd.Parameters.AddWithValue("$st", x.StatusCode);
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(x));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<HttpExchange> GetHttpExchanges(string? sessionId = null, string? search = null, int limit = 2000)
    {
        var list = new List<HttpExchange>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(sessionId))
        {
            where.Add("session_id=$sid");
            cmd.Parameters.AddWithValue("$sid", sessionId);
        }
        if (!string.IsNullOrWhiteSpace(search))
        {
            where.Add("(host LIKE $q OR path LIKE $q OR method LIKE $q)");
            cmd.Parameters.AddWithValue("$q", $"%{search}%");
        }
        cmd.CommandText = "SELECT json FROM http_exchanges " +
                          (where.Count > 0 ? "WHERE " + string.Join(" AND ", where) + " " : "") +
                          "ORDER BY rowid DESC LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var x = WslJson.Deserialize<HttpExchange>(reader.GetString(0));
            if (x is not null) list.Add(x);
        }
        list.Reverse();
        return list;
    }

    public HttpExchange? GetHttpExchange(string id)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM http_exchanges WHERE id=$id;";
        cmd.Parameters.AddWithValue("$id", id);
        return cmd.ExecuteScalar() is string json ? WslJson.Deserialize<HttpExchange>(json) : null;
    }

    // ------------------------------------------------------------- yara

    public void SaveYaraMatches(IEnumerable<YaraMatch> items)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var m in items)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = "INSERT INTO yara_matches(rule_name,file_path,severity,source,json) VALUES($r,$f,$s,$src,$json);";
            cmd.Parameters.AddWithValue("$r", m.RuleName);
            cmd.Parameters.AddWithValue("$f", m.FilePath);
            cmd.Parameters.AddWithValue("$s", m.Severity);
            cmd.Parameters.AddWithValue("$src", m.Source);
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(m));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<YaraMatch> GetYaraMatches(int limit = 2000)
    {
        var list = new List<YaraMatch>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT json FROM yara_matches ORDER BY id DESC LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var m = WslJson.Deserialize<YaraMatch>(reader.GetString(0));
            if (m is not null) list.Add(m);
        }
        return list;
    }

    // --------------------------------------------------------- findings

    public void SaveFindings(IEnumerable<Finding> findings)
    {
        using var conn = Open();
        using var tx = conn.BeginTransaction();
        foreach (var f in findings)
        {
            using var cmd = conn.CreateCommand();
            cmd.Transaction = tx;
            cmd.CommandText = """
                INSERT INTO findings(id,rule_id,severity,confidence,status,category,title,timestamp,json)
                VALUES($id,$r,$s,$c,$st,$cat,$t,$ts,$json)
                ON CONFLICT(id) DO UPDATE SET severity=$s, confidence=$c, status=$st, category=$cat, title=$t, json=$json;
                """;
            cmd.Parameters.AddWithValue("$id", f.Id);
            cmd.Parameters.AddWithValue("$r", f.RuleId);
            cmd.Parameters.AddWithValue("$s", (int)f.Severity);
            cmd.Parameters.AddWithValue("$c", (int)f.Confidence);
            cmd.Parameters.AddWithValue("$st", (int)f.Status);
            cmd.Parameters.AddWithValue("$cat", f.Category);
            cmd.Parameters.AddWithValue("$t", f.Title);
            cmd.Parameters.AddWithValue("$ts", f.Timestamp.ToString("O"));
            cmd.Parameters.AddWithValue("$json", WslJson.Serialize(f));
            cmd.ExecuteNonQuery();
        }
        tx.Commit();
    }

    public List<Finding> GetFindings(string? search = null, Severity? minSeverity = null, int limit = 1000)
    {
        var list = new List<Finding>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        var where = new List<string>();
        if (!string.IsNullOrWhiteSpace(search))
        {
            where.Add("(title LIKE $q OR rule_id LIKE $q OR category LIKE $q)");
            cmd.Parameters.AddWithValue("$q", $"%{search}%");
        }
        if (minSeverity is not null)
        {
            where.Add("severity>=$s");
            cmd.Parameters.AddWithValue("$s", (int)minSeverity.Value);
        }
        cmd.CommandText = "SELECT json FROM findings " +
                          (where.Count > 0 ? "WHERE " + string.Join(" AND ", where) + " " : "") +
                          "ORDER BY severity DESC, rowid LIMIT $n;";
        cmd.Parameters.AddWithValue("$n", limit);
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            var f = WslJson.Deserialize<Finding>(reader.GetString(0));
            if (f is not null) list.Add(f);
        }
        return list;
    }

    public void UpdateFindingStatus(string id, FindingStatus status)
    {
        var f = GetFindings().FirstOrDefault(x => x.Id == id);
        if (f is null) return;
        f.Status = status;
        SaveFindings(new[] { f });
    }

    public int NextFindingSerial()
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT COUNT(*) FROM findings;";
        return Convert.ToInt32(cmd.ExecuteScalar() ?? 0) + 101;
    }

    // ---------------------------------------------------------- reports

    public void SaveReport(string id, ReportFormat format, string path)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO reports(id,format,path,created_at) VALUES($id,$f,$p,$c);";
        cmd.Parameters.AddWithValue("$id", id);
        cmd.Parameters.AddWithValue("$f", format.ToString());
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$c", DateTime.Now.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    public List<(string Id, string Format, string Path, DateTime CreatedAt)> GetReports()
    {
        var list = new List<(string, string, string, DateTime)>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT id,format,path,created_at FROM reports ORDER BY created_at DESC;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            DateTime.TryParse(reader.GetString(3), out var created);
            list.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), created));
        }
        return list;
    }

    // --------------------------------------------------------- artifacts

    public void SaveArtifact(string sessionId, string kind, string name, string path, long size)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO artifacts(session_id,kind,name,path,size,created_at) VALUES($s,$k,$n,$p,$z,$c);";
        cmd.Parameters.AddWithValue("$s", sessionId);
        cmd.Parameters.AddWithValue("$k", kind);
        cmd.Parameters.AddWithValue("$n", name);
        cmd.Parameters.AddWithValue("$p", path);
        cmd.Parameters.AddWithValue("$z", size);
        cmd.Parameters.AddWithValue("$c", DateTime.Now.ToString("O"));
        cmd.ExecuteNonQuery();
    }

    public List<(string Kind, string Name, string Path, long Size, DateTime CreatedAt)> GetArtifacts()
    {
        var list = new List<(string, string, string, long, DateTime)>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT kind,name,path,size,created_at FROM artifacts ORDER BY created_at DESC;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            DateTime.TryParse(reader.GetString(4), out var created);
            list.Add((reader.GetString(0), reader.GetString(1), reader.GetString(2), reader.GetInt64(3), created));
        }
        return list;
    }

    public void AddNote(string author, string body)
    {
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "INSERT INTO notes(created_at,author,body) VALUES($c,$a,$b);";
        cmd.Parameters.AddWithValue("$c", DateTime.Now.ToString("O"));
        cmd.Parameters.AddWithValue("$a", author);
        cmd.Parameters.AddWithValue("$b", body);
        cmd.ExecuteNonQuery();
    }

    public List<(DateTime CreatedAt, string Author, string Body)> GetNotes()
    {
        var list = new List<(DateTime, string, string)>();
        using var conn = Open();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = "SELECT created_at,author,body FROM notes ORDER BY id DESC;";
        using var reader = cmd.ExecuteReader();
        while (reader.Read())
        {
            DateTime.TryParse(reader.GetString(0), out var created);
            list.Add((created, reader.GetString(1), reader.GetString(2)));
        }
        return list;
    }

    /// <summary>仪表盘统计。</summary>
    public ProjectStatistics GetStatistics()
    {
        using var conn = Open();
        var stats = new ProjectStatistics();
        using var cmd = conn.CreateCommand();
        cmd.CommandText = """
            SELECT
              (SELECT COUNT(*) FROM evidence),
              (SELECT COUNT(*) FROM events),
              (SELECT COUNT(*) FROM events WHERE is_suspicious=1),
              (SELECT COUNT(*) FROM connections),
              (SELECT COUNT(*) FROM connections WHERE domain IS NOT NULL AND domain<>''),
              (SELECT COUNT(*) FROM http_exchanges),
              (SELECT COUNT(*) FROM yara_matches),
              (SELECT COUNT(*) FROM findings),
              (SELECT COUNT(*) FROM findings WHERE severity>=3),
              (SELECT COUNT(*) FROM dependencies WHERE is_user_writable=1),
              (SELECT COUNT(*) FROM pe_images);
            """;
        using var reader = cmd.ExecuteReader();
        if (reader.Read())
        {
            stats.EvidenceCount = reader.GetInt32(0);
            stats.EventCount = reader.GetInt32(1);
            stats.SuspiciousEventCount = reader.GetInt32(2);
            stats.ConnectionCount = reader.GetInt32(3);
            stats.ResolvedDomainCount = reader.GetInt32(4);
            stats.HttpExchangeCount = reader.GetInt32(5);
            stats.YaraMatchCount = reader.GetInt32(6);
            stats.FindingCount = reader.GetInt32(7);
            stats.HighSeverityCount = reader.GetInt32(8);
            stats.UserWritableDependencyCount = reader.GetInt32(9);
            stats.PeImageCount = reader.GetInt32(10);
        }
        stats.SeverityCounts = new int[5];
        using var sevCmd = conn.CreateCommand();
        sevCmd.CommandText = "SELECT severity, COUNT(*) FROM findings GROUP BY severity;";
        using var sevReader = sevCmd.ExecuteReader();
        while (sevReader.Read())
        {
            var idx = sevReader.GetInt32(0);
            if (idx is >= 0 and < 5) stats.SeverityCounts[idx] = sevReader.GetInt32(1);
        }
        return stats;
    }
}

public sealed class ProjectStatistics
{
    public int EvidenceCount { get; set; }
    public int EventCount { get; set; }
    public int SuspiciousEventCount { get; set; }
    public int ConnectionCount { get; set; }
    public int ResolvedDomainCount { get; set; }
    public int HttpExchangeCount { get; set; }
    public int YaraMatchCount { get; set; }
    public int FindingCount { get; set; }
    public int HighSeverityCount { get; set; }
    public int UserWritableDependencyCount { get; set; }
    public int PeImageCount { get; set; }
    public int[] SeverityCounts { get; set; } = new int[5];

    public int CriticalCount => SeverityCounts[4];
    public int HighCount => SeverityCounts[3];
    public int MediumCount => SeverityCounts[2];
    public int LowCount => SeverityCounts[1];
    public int InfoCount => SeverityCounts[0];
}
