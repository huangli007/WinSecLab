using System.Collections.ObjectModel;
using System.ComponentModel;
using System.Globalization;
using System.Runtime.CompilerServices;
using System.Windows;
using System.Windows.Data;
using System.Windows.Input;
using System.Windows.Media;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Infrastructure;

/// <summary>极简 MVVM 基类。刻意不引入 CommunityToolkit，减少分发依赖。</summary>
public abstract class ObservableObject : INotifyPropertyChanged
{
    public event PropertyChangedEventHandler? PropertyChanged;

    protected void Raise([CallerMemberName] string? name = null) =>
        PropertyChanged?.Invoke(this, new PropertyChangedEventArgs(name));

    protected bool Set<T>(ref T field, T value, [CallerMemberName] string? name = null)
    {
        if (EqualityComparer<T>.Default.Equals(field, value)) return false;
        field = value;
        Raise(name);
        return true;
    }
}

public sealed class RelayCommand : ICommand
{
    private readonly Action<object?> _execute;
    private readonly Func<object?, bool>? _canExecute;

    public RelayCommand(Action execute, Func<bool>? canExecute = null)
    {
        _execute = _ => execute();
        _canExecute = canExecute is null ? null : _ => canExecute();
    }

    public RelayCommand(Action<object?> execute, Func<object?, bool>? canExecute = null)
    {
        _execute = execute;
        _canExecute = canExecute;
    }

    public event EventHandler? CanExecuteChanged;

    public bool CanExecute(object? parameter) => _canExecute?.Invoke(parameter) ?? true;

    public void Execute(object? parameter) => _execute(parameter);

    public void RaiseCanExecuteChanged() => CanExecuteChanged?.Invoke(this, EventArgs.Empty);
}

/// <summary>UI 线程安全的集合：后台线程采集到的数据统一从这里进入绑定。</summary>
public sealed class UiDispatcher
{
    public static void Invoke(Action action)
    {
        var dispatcher = Application.Current?.Dispatcher;
        if (dispatcher is null || dispatcher.CheckAccess()) action();
        else dispatcher.BeginInvoke(action);
    }
}

// ═════════════════════════════ 转换器 ═════════════════════════════

/// <summary>严重级 → 前景色 / 底色 / 中文标签。</summary>
public sealed class SeverityBrushConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var mode = parameter as string ?? "fg";
        var sev = value switch
        {
            Severity s => s,
            string str when Enum.TryParse<Severity>(str, true, out var p) => p,
            _ => Severity.Info,
        };

        var (fg, bg) = sev switch
        {
            Severity.Critical => ("#B91C1C", "#FEE7E7"),
            Severity.High => ("#DC2626", "#FDE8E8"),
            Severity.Medium => ("#D97706", "#FEF3E2"),
            Severity.Low => ("#0284C7", "#E4F2FA"),
            _ => ("#64748B", "#EEF1F5"),
        };

        return mode == "bg" ? Brush(bg) : Brush(fg);
    }

    private static SolidColorBrush Brush(string hex)
    {
        var b = new SolidColorBrush((Color)ColorConverter.ConvertFromString(hex));
        b.Freeze();
        return b;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class SeverityTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture) =>
        value is Severity s ? s switch
        {
            Severity.Critical => "严重",
            Severity.High => "高",
            Severity.Medium => "中",
            Severity.Low => "低",
            _ => "提示",
        } : "";

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class BoolToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var flag = value is bool b && b;
        if (parameter as string == "invert") flag = !flag;
        return flag ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

/// <summary>把任意字符串按参数长度截断（表格里长路径用）。</summary>
public sealed class TruncateConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var text = value?.ToString() ?? "";
        var max = int.TryParse(parameter as string, out var m) ? m : 60;
        if (text.Length <= max) return text;
        return "…" + text[^(max - 1)..];
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

/// <summary>非空字符串 → 显示（用于徽标一类"有内容才出现"的元素）。</summary>
public sealed class StringToVisibilityConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var has = !string.IsNullOrWhiteSpace(value?.ToString());
        if (parameter as string == "invert") has = !has;
        return has ? Visibility.Visible : Visibility.Collapsed;
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

public sealed class BoolToTextConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var parts = (parameter as string ?? "是|否").Split('|');
        var flag = value is bool b && b;
        return flag ? parts[0] : parts.Length > 1 ? parts[1] : "";
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}

/// <summary>文件名（表格里显示路径的可读尾部）。</summary>
public sealed class FileNameConverter : IValueConverter
{
    public object Convert(object value, Type targetType, object parameter, CultureInfo culture)
    {
        var path = value?.ToString();
        if (string.IsNullOrWhiteSpace(path)) return "";
        try { return Path.GetFileName(path) ?? path; }
        catch { return path; }
    }

    public object ConvertBack(object value, Type targetType, object parameter, CultureInfo culture) =>
        Binding.DoNothing;
}
