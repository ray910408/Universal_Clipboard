using System.Xml.Linq;
using FluentAssertions;

namespace UniversalClipboard.App.Tests;

public sealed class ProjectShapeTests
{
    [Fact]
    public void App_is_windows_winforms_with_aspnet_framework_and_core_reference()
    {
        var root = FindRepositoryRoot();
        var project = XDocument.Load(
            Path.Combine(root, "src", "UniversalClipboard.App", "UniversalClipboard.App.csproj"));

        ProjectValue(project, "OutputType").Should().Be("WinExe");
        ProjectValue(project, "AssemblyName").Should().Be("UniversalClipboard");
        ProjectValue(project, "RootNamespace").Should().Be("UniversalClipboard.App");
        ProjectValue(project, "Product").Should().Be("Universal Clipboard");
        ProjectValue(project, "TargetFramework").Should().Be("net10.0-windows");
        ProjectValue(project, "UseWindowsForms").Should().Be("true");
        ProjectIncludes(project, "FrameworkReference").Should().ContainSingle()
            .Which.Should().Be("Microsoft.AspNetCore.App");
        ProjectIncludes(project, "ProjectReference").Should().ContainSingle()
            .Which.Replace('\\', '/').Should().Be("../UniversalClipboard.Core/UniversalClipboard.Core.csproj");
    }

    [Fact]
    public void Core_project_does_not_reference_app_or_aspnet()
    {
        var root = FindRepositoryRoot();
        var project = XDocument.Load(
            Path.Combine(root, "src", "UniversalClipboard.Core", "UniversalClipboard.Core.csproj"));

        ProjectIncludes(project, "ProjectReference").Should().BeEmpty();
        ProjectIncludes(project, "FrameworkReference").Should().BeEmpty();
        project.ToString().Should().NotContain("UniversalClipboard.App");
        project.ToString().Should().NotContain("Microsoft.AspNetCore");
    }

    private static string ProjectValue(XDocument project, string name) =>
        project.Descendants(name).Single().Value;

    private static string[] ProjectIncludes(XDocument project, string itemName) =>
        project.Descendants(itemName)
            .Select(item => item.Attribute("Include")?.Value)
            .Where(value => value is not null)
            .Select(value => value!)
            .ToArray();

    private static string FindRepositoryRoot()
    {
        var directory = new DirectoryInfo(AppContext.BaseDirectory);
        while (directory is not null && !File.Exists(Path.Combine(directory.FullName, "UniversalClipboard.slnx")))
        {
            directory = directory.Parent;
        }

        return directory?.FullName ??
            throw new DirectoryNotFoundException("Could not locate the repository root.");
    }
}
