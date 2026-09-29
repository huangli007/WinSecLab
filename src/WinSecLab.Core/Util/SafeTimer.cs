namespace WinSecLab.Core.Util;

/// <summary>
/// 定时器工厂：保证回调里的异常不会杀掉进程。
///
/// 为什么必须这样做：<see cref="System.Threading.Timer"/> 的回调在线程池上执行，
/// 抛出的异常属于"未处理异常"，会直接终止整个进程 —— 而且 Timer 回调的堆栈里
/// 看不到任何业务代码上下文，排查成本极高。
/// 对监控类工具来说，一个畸形路径 / 一个瞬时报错的 WMI 查询就能让整场分析崩掉，
/// 这是不可接受的：监控必须比被监控对象更稳。
/// </summary>
public static class SafeTimer
{
    public static Timer Create(Action callback, int dueMs, int periodMs, Action<Exception>? onError = null)
    {
        return new Timer(_ =>
        {
            try
            {
                callback();
            }
            catch (Exception ex)
            {
                // 默认静默：定时轮询的偶发失败不该刷屏，但调用方可以通过 onError 收集
                onError?.Invoke(ex);
            }
        }, null, dueMs, periodMs);
    }
}
