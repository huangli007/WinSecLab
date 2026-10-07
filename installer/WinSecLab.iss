; ─────────────────────────────────────────────────────────────────────────────
; WinSecLab 安装包脚本（Inno Setup 6）
;
; 产物：dist/installer/WinSecLab-Setup-<版本>.exe
;
; 设计取舍：
;  · 安装到 {autopf}\WinSecLab（默认 Program Files，需要 UAC；这是安装程序该有的行为）。
;    程序本身是 asInvoker 的，装完点快捷方式不会每次弹 UAC。
;  · 开始菜单 + 可选桌面快捷方式；同时注册到「应用和功能」，带卸载入口。
;  · 附带一条 PATH 可选项：把安装目录加入用户 PATH，方便命令行直接用 wsx。
;  · 安装包内含已发布好的自包含单文件（无需目标机装 .NET 运行时）。
;
; 编译前请先跑 bash publish.sh（产物在 dist/win-x64/）。
; ─────────────────────────────────────────────────────────────────────────────

#define AppName        "WinSecLab"
#define AppVersion     "0.1.0"
#define AppPublisher   "WinSecLab"
#define AppExeName     "WinSecLab.exe"
#define CliExeName     "wsx.exe"
#define AppId          "{{9E2A7C41-5B3D-4F0A-9C6E-7A1D4B8F2E30}"
#define SourceDir      "..\dist\win-x64"

[Setup]
; AppId 唯一标识本应用，升级时复用（不要改）
AppId={#AppId}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#AppVersion}
VersionInfoProductName={#AppName}
VersionInfoCompany={#AppPublisher}
VersionInfoDescription={#AppName} 安装程序 — Windows PC 应用综合安全测试平台

; 默认安装目录：优先 64 位程序目录，普通用户则装到本地 AppData
DefaultDirName={autopf}\{#AppName}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
UninstallDisplayName={#AppName}
UninstallDisplayIcon={app}\{#AppExeName}

; 仅 64 位；WinSecLab 只发布 win-x64
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible

; 权限策略：默认**当前用户安装**（免 UAC，装到 %LOCALAPPDATA%\Programs），
; 用户可在向导里选择"为所有用户安装"（需管理员，装到 Program Files）。
; 这样普通用户双击即装、无需管理员，是桌面工具更友好的默认。
PrivilegesRequired=lowest
PrivilegesRequiredOverridesAllowed=dialog

; 输出
OutputDir=..\dist\installer
OutputBaseFilename={#AppName}-Setup-{#AppVersion}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupIconFile=..\src\WinSecLab.App\Assets\wsl.ico
DisableWelcomePage=no
LicenseFile=..\LICENSE
; 允许用户在向导里改安装路径
DisableDirPage=no

[Languages]
; 简体中文放第一位 = 安装向导默认语言。
; ChineseSimplified.isl 是社区维护的官方收录语言包，随仓库放在 installer/ 目录，
; 保证任何机器编译都能用（Inno 自带 29 种语言但不含中文）。
Name: "chinesesimplified"; MessagesFile: "ChineseSimplified.isl"
Name: "english"; MessagesFile: "compiler:Default.isl"

[CustomMessages]
chinesesimplified.CreateDesktopIcon=创建桌面快捷方式
english.CreateDesktopIcon=Create a desktop shortcut
chinesesimplified.AddToPath=把安装目录加入 PATH（命令行可直接使用 wsx）
english.AddToPath=Add install directory to PATH (use wsx from the command line)
chinesesimplified.AdditionalIcons=附加快捷方式：
english.AdditionalIcons=Additional shortcuts:
chinesesimplified.EnvConfig=环境配置：
english.EnvConfig=Environment:
chinesesimplified.LaunchApp=立即启动 WinSecLab
english.LaunchApp=Launch WinSecLab now
chinesesimplified.ManualShortcut=WinSecLab 使用手册
english.ManualShortcut=WinSecLab User Manual

[Tasks]
Name: "desktopicon"; Description: "{cm:CreateDesktopIcon}"; GroupDescription: "{cm:AdditionalIcons}"; Flags: unchecked
Name: "addtopath";    Description: "{cm:AddToPath}";        GroupDescription: "{cm:EnvConfig}"; Flags: unchecked

[Files]
; 主体：已发布的目录（两个自包含单文件 + 相关资源）
Source: "{#SourceDir}\WinSecLab.exe"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourceDir}\wsx.exe";       DestDir: "{app}"; Flags: ignoreversion
; 其余发布文件（排除调试符号 .pdb —— 对最终用户无意义）
Source: "{#SourceDir}\*";             DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "*.pdb"
; 文档
Source: "..\README.md";               DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\使用手册.md";              DestDir: "{app}\docs"; Flags: ignoreversion
Source: "..\LICENSE";                 DestDir: "{app}\docs"; Flags: ignoreversion

[Icons]
; 开始菜单
Name: "{group}\{#AppName}";              Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\{#AppExeName}"
Name: "{group}\{cm:ManualShortcut}";     Filename: "{app}\docs\使用手册.md"
Name: "{group}\卸载 {#AppName}";          Filename: "{uninstallexe}"
; 桌面（可选）
Name: "{autodesktop}\{#AppName}";        Filename: "{app}\{#AppExeName}"; IconFilename: "{app}\{#AppExeName}"; Tasks: desktopicon

[Run]
; 安装完成后可选直接启动
Filename: "{app}\{#AppExeName}"; Description: "{cm:LaunchApp}"; Flags: nowait postinstall skipifsilent

[Registry]
; 可选：把安装目录加进用户 PATH（卸载时移除）
Root: HKCU; Subkey: "Environment"; ValueType: expandsz; ValueName: "Path"; \
    ValueData: "{olddata};{app}"; Check: NeedsAddPath(ExpandConstant('{app}')); \
    Flags: preservestringtype; Tasks: addtopath

[UninstallRun]

[Code]
const
  EnvironmentKey = 'Environment';

{ 判断 PATH 里是否已经包含目标目录（大小写不敏感） }
function NeedsAddPath(Param: string): Boolean;
var
  OrigPath: string;
begin
  if not RegQueryStringValue(HKCU, EnvironmentKey, 'Path', OrigPath) then begin
    Result := True;
    exit;
  end;
  { 用分号包裹做精确匹配，避免 "C:\App" 命中 "C:\App2" }
  Result := Pos(';' + Uppercase(Param) + ';', ';' + Uppercase(OrigPath) + ';') = 0;
end;

{ 卸载时从用户 PATH 移除本目录 }
procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  OrigPath, NewPath, AppDir: string;
  P: Integer;
begin
  if CurUninstallStep = usPostUninstall then begin
    AppDir := ExpandConstant('{app}');
    if RegQueryStringValue(HKCU, EnvironmentKey, 'Path', OrigPath) then begin
      NewPath := OrigPath;
      { 去掉分号加安装目录 }
      P := Pos(';' + Uppercase(AppDir), Uppercase(NewPath));
      if P > 0 then
        Delete(NewPath, P, Length(AppDir) + 1);
      { 也处理开头就是安装目录的情况 }
      if Uppercase(Copy(NewPath, 1, Length(AppDir))) = Uppercase(AppDir) then
        Delete(NewPath, 1, Length(AppDir) + 1);
      RegWriteExpandStringValue(HKCU, EnvironmentKey, 'Path', NewPath);
    end;
  end;
end;
