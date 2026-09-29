using System.Windows;
using WinSecLab.Core.Models;

namespace WinSecLab.App.Views;

/// <summary>
/// 编辑项目元数据的模态对话框（名称/描述/执行人/授权信息）。
///
/// 项目名往往是随手起的，授权信息也常是事后才拿到的，创建后必须能改。
/// 这里只编辑元数据，不碰目录名 —— 见 WorkspaceService.UpdateProject 的说明。
/// </summary>
public partial class ProjectEditDialog : Window
{
    public string ProjectName => NameBox.Text.Trim();
    public string Description => DescriptionBox.Text.Trim();
    public string Author => AuthorBox.Text.Trim();
    public string Authorization => AuthorizationBox.Text.Trim();

    public ProjectEditDialog(TestProject project)
    {
        InitializeComponent();

        NameBox.Text = project.Name;
        DescriptionBox.Text = project.Description ?? "";
        AuthorBox.Text = project.Author ?? "";
        AuthorizationBox.Text = project.Authorization ?? "";

        Loaded += (_, _) =>
        {
            NameBox.Focus();
            NameBox.SelectAll();
        };
    }

    /// <summary>校验失败时在对话框内提示，而不是关掉窗口让用户重来。</summary>
    public void ShowError(string message)
    {
        ErrorText.Text = message;
        ErrorText.Visibility = Visibility.Visible;
    }

    private void Save_OnClick(object sender, RoutedEventArgs e)
    {
        if (string.IsNullOrWhiteSpace(NameBox.Text))
        {
            ShowError("项目名称不能为空。");
            return;
        }

        DialogResult = true;
    }

    private void Cancel_OnClick(object sender, RoutedEventArgs e) => DialogResult = false;
}
