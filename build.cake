#addin "nuget:?package=Cake.Git&version=0.22.0"
#addin "nuget:?package=Cake.CMake&version=1.2.0"

//////////////////////////////////////////////////////////////////////
// ARGUMENTS
//////////////////////////////////////////////////////////////////////

var configuration = Argument("configuration", "Debug");
var revision = EnvironmentVariable("BUILD_NUMBER") ?? Argument("revision", "9999");
var target = Argument("target", "Default");
var cmakeToolset = EnvironmentVariable("CMAKE_TOOLSET") ?? "v141";
var cmakeWithArm64EcBinary = EnvironmentVariable("CMAKE_WITH_ARM64EC_BINARY") ?? "ON";
var cmakeWithArmBinary = EnvironmentVariable("CMAKE_WITH_ARM_BINARY") ?? "ON";
var cmakeWithSharedVcrt = EnvironmentVariable("CMAKE_WITH_SHARED_VCRT") ?? "OFF";
var cmakeWithStaticVcrt = EnvironmentVariable("CMAKE_WITH_STATIC_VCRT") ?? "ON";
var cmakeWithTestRunner = EnvironmentVariable("CMAKE_WITH_TEST_RUNNER") ?? "OFF";
var cmakeWithWorkaroundArm64Rt = EnvironmentVariable("CMAKE_WITH_WORKAROUND_ARM64RT") ?? "OFF";


//////////////////////////////////////////////////////////////////////
// PREPARATION
//////////////////////////////////////////////////////////////////////

// Define git commit id
var commitId = "SNAPSHOT";

// Define product name and version
var product = "vita_core_api";
var productDescription = "HTC Vita Core API";
var companyName = "HTC";
var version = "0.9.0";
var semanticVersion = string.Format("{0}.{1}", version, revision);
var ciVersion = string.Format("{0}.{1}", version, "0");
var nugetTags = new [] {"htc", "vita", "core"};
var projectUrl = "https://github.com/ViveportSoftware/vita_core_api/";
var msbuildSettings = new MSBuildSettings()
{
        Configuration = configuration,
        MaxCpuCount = 0
};
var cmakeOptions = new List<string>();
cmakeOptions.Add("-DBUILD_WITH_SHARED_VCRT=" + cmakeWithSharedVcrt);
cmakeOptions.Add("-DBUILD_WITH_STATIC_VCRT=" + cmakeWithStaticVcrt);
cmakeOptions.Add("-DBUILD_WITH_TEST_RUNNER=" + cmakeWithTestRunner);
cmakeOptions.Add("-DMY_PROJECT_DESC=" + productDescription);
cmakeOptions.Add("-DMY_PROJECT_NAME=" + product);
cmakeOptions.Add("-DMY_REVISION=" + revision);
cmakeOptions.Add("-DMY_VER=" + version);
var isReleaseBuild = "Release".Equals(configuration) || "RelWithDebInfo".Equals(configuration);

// Define copyright
var copyright = string.Format("Copyright © 2018 - {0}", DateTime.Now.Year);

// Define timestamp for signing
var lastSignTimestamp = DateTime.Now;
var signIntervalInMilli = 1000 * 5;

// Define directories.
var sourceDir = Directory("./source");
var distDir = Directory("./dist");
var tempDir = Directory("./temp");
var packagesDir = Directory("./source/packages");
var nugetDir = Directory("./dist") + Directory(configuration) + Directory("nuget");
var homeDir = Directory(EnvironmentVariable("USERPROFILE") ?? EnvironmentVariable("HOME"));
var tempPlatformDirARM = tempDir + Directory(configuration) + Directory("ARM");
var tempPlatformDirARM64 = tempDir + Directory(configuration) + Directory("ARM64");
var tempPlatformDirARM64EC = tempDir + Directory(configuration) + Directory("ARM64EC");
var tempPlatformDirWin32 = tempDir + Directory(configuration) + Directory("Win32");
var tempPlatformDirX64 = tempDir + Directory(configuration) + Directory("x64");
var msbuildDefaultTargetARM = File(tempPlatformDirARM.ToString() + "/" + product + ".sln");
var msbuildDefaultTargetARM64 = File(tempPlatformDirARM64.ToString() + "/" + product + ".sln");
var msbuildDefaultTargetARM64EC = File(tempPlatformDirARM64EC.ToString() + "/" + product + ".sln");
var msbuildDefaultTargetWin32 = File(tempPlatformDirWin32.ToString() + "/" + product + ".sln");
var msbuildDefaultTargetX64 = File(tempPlatformDirX64.ToString() + "/" + product + ".sln");
var msbuildCTestTargetARM = File(tempPlatformDirARM.ToString() + "/RUN_TESTS.vcxproj");
var msbuildCTestTargetARM64 = File(tempPlatformDirARM64.ToString() + "/RUN_TESTS.vcxproj");
var msbuildCTestTargetARM64EC = File(tempPlatformDirARM64EC.ToString() + "/RUN_TESTS.vcxproj");
var msbuildCTestTargetWin32 = File(tempPlatformDirWin32.ToString() + "/RUN_TESTS.vcxproj");
var msbuildCTestTargetX64 = File(tempPlatformDirX64.ToString() + "/RUN_TESTS.vcxproj");

// Define signing key, password and timestamp server
var signKeyEnc = EnvironmentVariable("SIGNKEYENC") ?? "NOTSET";
var signPass = EnvironmentVariable("SIGNPASS") ?? "NOTSET";
var signSha1Uri = new Uri("http://timestamp.digicert.com");
var signSha256Uri = new Uri("http://timestamp.digicert.com");

// Define nuget push source and key
var nugetApiKey = EnvironmentVariable("NUGET_PUSH_TOKEN") ?? EnvironmentVariable("NUGET_APIKEY") ?? "NOTSET";
var nugetSource = EnvironmentVariable("NUGET_PUSH_PATH") ?? EnvironmentVariable("NUGET_SOURCE") ?? "NOTSET";


//////////////////////////////////////////////////////////////////////
// TASKS
//////////////////////////////////////////////////////////////////////

Task("Fetch-Git-Commit-ID")
    .ContinueOnError()
    .Does(() =>
{
    var lastCommit = GitLogTip(MakeAbsolute(Directory(".")));
    commitId = lastCommit.Sha;
});

Task("Display-Config")
    .IsDependentOn("Fetch-Git-Commit-ID")
    .Does(() =>
{
    Information("Build target: {0}", target);
    Information("Build configuration: {0}", configuration);
    Information("Build commitId: {0}", commitId);
    if (isReleaseBuild)
    {
        Information("Build version: {0}", semanticVersion);
    }
    else
    {
        Information("Build version: {0}-CI{1}", ciVersion, revision);
    }
});

Task("Clean-Workspace")
    .IsDependentOn("Display-Config")
    .Does(() =>
{
    CleanDirectory(distDir);
    CleanDirectory(tempDir);
    CleanDirectory(packagesDir);
});

Task("Build-Binary-Win32")
    .IsDependentOn("Clean-Workspace")
    .Does(() =>
{
    if(IsRunningOnWindows())
    {
        CreateDirectory(tempPlatformDirWin32);
        var cmakeSettings = new CMakeSettings
        {
                Options = cmakeOptions.ToArray(),
                OutputPath = tempPlatformDirWin32,
                Platform = "Win32"
        };
        if (!string.IsNullOrEmpty(cmakeToolset))
        {
            cmakeSettings.Toolset = cmakeToolset;
        }
        CMake(
                sourceDir,
                cmakeSettings
        );
        MSBuild(
                msbuildDefaultTargetWin32,
                msbuildSettings
        );
    }
});

Task("Build-Binary-ARM")
    .WithCriteria(() => ("v140".Equals(cmakeToolset) || "v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
    .IsDependentOn("Build-Binary-Win32")
    .Does(() =>
{
    if(IsRunningOnWindows())
    {
        CreateDirectory(tempPlatformDirARM);
        var cmakeSettings = new CMakeSettings
        {
                Options = cmakeOptions.ToArray(),
                OutputPath = tempPlatformDirARM,
                Platform = "ARM"
        };
        if (!string.IsNullOrEmpty(cmakeToolset))
        {
            cmakeSettings.Toolset = cmakeToolset;
        }
        CMake(
                sourceDir,
                cmakeSettings
        );
        MSBuild(
                msbuildDefaultTargetARM,
                msbuildSettings
        );
    }
});

Task("Build-Binary-x64")
    .WithCriteria(() => "v140".Equals(cmakeToolset) || "v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset))
    .IsDependentOn("Build-Binary-ARM")
    .Does(() =>
{
    if(IsRunningOnWindows())
    {
        CreateDirectory(tempPlatformDirX64);
        cmakeOptions.Add("-DMY_PROJECT_SUFFIX=64");
        var cmakeSettings = new CMakeSettings
        {
                Options = cmakeOptions.ToArray(),
                OutputPath = tempPlatformDirX64,
                Platform = "x64"
        };
        if (!string.IsNullOrEmpty(cmakeToolset))
        {
            cmakeSettings.Toolset = cmakeToolset;
        }
        CMake(
                sourceDir,
                cmakeSettings
        );
        MSBuild(
                msbuildDefaultTargetX64,
                msbuildSettings
        );
    }
});

Task("Build-Binary-ARM64")
    .WithCriteria(() => ("v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
    .IsDependentOn("Build-Binary-x64")
    .Does(() =>
{
    if(IsRunningOnWindows())
    {
        CreateDirectory(tempPlatformDirARM64);
        var cmakeOptionsArm64 = new List<string>(cmakeOptions);
        if ("ON".Equals(cmakeWithWorkaroundArm64Rt))
        {
            cmakeOptionsArm64.Add("-DBUILD_WITH_WORKAROUND_ARM64RT=ON");
        }
        var cmakeSettings = new CMakeSettings
        {
                Options = cmakeOptionsArm64.ToArray(),
                OutputPath = tempPlatformDirARM64,
                Platform = "ARM64"
        };
        if (!string.IsNullOrEmpty(cmakeToolset))
        {
            cmakeSettings.Toolset = cmakeToolset;
        }
        CMake(
                sourceDir,
                cmakeSettings
        );
        MSBuild(
                msbuildDefaultTargetARM64,
                msbuildSettings
        );
    }
});

Task("Build-Binary-ARM64EC")
    .WithCriteria(() => ("v142".Equals(cmakeToolset) || "v143".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArm64EcBinary))
    .IsDependentOn("Build-Binary-ARM64")
    .Does(() =>
{
    if(IsRunningOnWindows())
    {
        CreateDirectory(tempPlatformDirARM64EC);
        var cmakeOptionsArm64Ec = new List<string>(cmakeOptions);
        cmakeOptionsArm64Ec.Add("-DBUILD_WITH_WORKAROUND_SOFTINTRIN=ON");
        var cmakeSettings = new CMakeSettings
        {
                Options = cmakeOptionsArm64Ec.ToArray(),
                OutputPath = tempPlatformDirARM64EC,
                Platform = "ARM64EC"
        };
        if (!string.IsNullOrEmpty(cmakeToolset))
        {
            cmakeSettings.Toolset = cmakeToolset;
        }
        CMake(
                sourceDir,
                cmakeSettings
        );
        MSBuild(
                msbuildDefaultTargetARM64EC,
                msbuildSettings
        );
    }
});

Task("Test-Binary-Win32")
    .WithCriteria(() => FileExists(msbuildCTestTargetWin32))
    .IsDependentOn("Build-Binary-ARM64EC")
    .Does(() =>
{
    if(IsRunningOnWindows())
    {
        MSBuild(
                msbuildCTestTargetWin32,
                msbuildSettings
        );
    }
});

Task("Test-Binary-x64")
    .WithCriteria(() => FileExists(msbuildCTestTargetX64))
    .IsDependentOn("Test-Binary-Win32")
    .Does(() =>
{
    if(IsRunningOnWindows())
    {
        MSBuild(
                msbuildCTestTargetX64,
                msbuildSettings
        );
    }
});

Task("Sign-Binaries")
    .WithCriteria(() => isReleaseBuild && !"NOTSET".Equals(signPass) && !"NOTSET".Equals(signKeyEnc))
    .IsDependentOn("Test-Binary-x64")
    .Does(() =>
{
    var currentSignTimestamp = DateTime.Now;
    Information("Last timestamp:    " + lastSignTimestamp);
    Information("Current timestamp: " + currentSignTimestamp);
    var totalTimeInMilli = (DateTime.Now - lastSignTimestamp).TotalMilliseconds;

    var signKey = "./temp/key.pfx";
    System.IO.File.WriteAllBytes(signKey, Convert.FromBase64String(signKeyEnc));

    var file = string.Format("./temp/{0}/x64/{0}/{1}64.dll", configuration, product);

    if (totalTimeInMilli < signIntervalInMilli)
    {
        System.Threading.Thread.Sleep(signIntervalInMilli - (int)totalTimeInMilli);
    }
    Sign(
            file,
            new SignToolSignSettings
            {
                    AppendSignature = true,
                    TimeStampUri = signSha256Uri,
                    DigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                    TimeStampDigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                    CertPath = signKey,
                    Password = signPass
            }
    );
    lastSignTimestamp = DateTime.Now;

    file = string.Format("./temp/{0}/Win32/{0}/{1}.dll", configuration, product);

    if (totalTimeInMilli < signIntervalInMilli)
    {
        System.Threading.Thread.Sleep(signIntervalInMilli - (int)totalTimeInMilli);
    }
    Sign(
            file,
            new SignToolSignSettings
            {
                    AppendSignature = true,
                    TimeStampUri = signSha256Uri,
                    DigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                    TimeStampDigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                    CertPath = signKey,
                    Password = signPass
            }
    );
    lastSignTimestamp = DateTime.Now;

    if (("v140".Equals(cmakeToolset) || "v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
    {
        file = string.Format("./temp/{0}/ARM/{0}/{1}.dll", configuration, product);

        if (totalTimeInMilli < signIntervalInMilli)
        {
            System.Threading.Thread.Sleep(signIntervalInMilli - (int)totalTimeInMilli);
        }
        Sign(
                file,
                new SignToolSignSettings
                {
                        AppendSignature = true,
                        TimeStampUri = signSha256Uri,
                        DigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                        TimeStampDigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                        CertPath = signKey,
                        Password = signPass
                }
        );
        lastSignTimestamp = DateTime.Now;
    }

    if (("v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
    {
        file = string.Format("./temp/{0}/ARM64/{0}/{1}64.dll", configuration, product);

        if (totalTimeInMilli < signIntervalInMilli)
        {
            System.Threading.Thread.Sleep(signIntervalInMilli - (int)totalTimeInMilli);
        }
        Sign(
                file,
                new SignToolSignSettings
                {
                        AppendSignature = true,
                        TimeStampUri = signSha256Uri,
                        DigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                        TimeStampDigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                        CertPath = signKey,
                        Password = signPass
                }
        );
        lastSignTimestamp = DateTime.Now;
    }

    if (("v142".Equals(cmakeToolset) || "v143".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArm64EcBinary))
    {
        file = string.Format("./temp/{0}/ARM64EC/{0}/{1}64.dll", configuration, product);

        if (totalTimeInMilli < signIntervalInMilli)
        {
            System.Threading.Thread.Sleep(signIntervalInMilli - (int)totalTimeInMilli);
        }
        Sign(
                file,
                new SignToolSignSettings
                {
                        AppendSignature = true,
                        TimeStampUri = signSha256Uri,
                        DigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                        TimeStampDigestAlgorithm = SignToolDigestAlgorithm.Sha256,
                        CertPath = signKey,
                        Password = signPass
                }
        );
        lastSignTimestamp = DateTime.Now;
    }
});

Task("Build-NuGet-Package")
    .IsDependentOn("Sign-Binaries")
    .Does(() =>
{
    CreateDirectory(nugetDir);
    var nugetPackVersion = semanticVersion;
    if (!isReleaseBuild)
    {
        nugetPackVersion = string.Format("{0}-CI{1}", ciVersion, revision);
    }
    Information("Pack version: {0}", nugetPackVersion);

    var nuspecContents = new List<NuSpecContent>();
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("x64/{0}/{1}64.dll", configuration, product),
                    Target = "lib\\x64"
            }
    );
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("x64/{0}/{1}64.lib", configuration, product),
                    Target = "lib\\x64"
            }
    );
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("x64/{0}/{1}64_static.lib", configuration, product),
                    Target = "lib\\x64"
            }
    );
    if (("v142".Equals(cmakeToolset) || "v143".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArm64EcBinary))
    {
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM64EC/{0}/{1}64.dll", configuration, product),
                        Target = "lib\\ARM64EC"
                }
        );
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM64EC/{0}/{1}64.lib", configuration, product),
                        Target = "lib\\ARM64EC"
                }
        );
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM64EC/{0}/{1}64_static.lib", configuration, product),
                        Target = "lib\\ARM64EC"
                }
        );
    }
    if (("v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
    {
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM64/{0}/{1}64.dll", configuration, product),
                        Target = "lib\\ARM64"
                }
        );
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM64/{0}/{1}64.lib", configuration, product),
                        Target = "lib\\ARM64"
                }
        );
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM64/{0}/{1}64_static.lib", configuration, product),
                        Target = "lib\\ARM64"
                }
        );
    }
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("Win32/{0}/{1}.dll", configuration, product),
                    Target = "lib\\Win32"
            }
    );
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("Win32/{0}/{1}.lib", configuration, product),
                    Target = "lib\\Win32"
            }
    );
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("Win32/{0}/{1}_static.lib", configuration, product),
                    Target = "lib\\Win32"
            }
    );
    if (("v140".Equals(cmakeToolset) || "v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
    {
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM/{0}/{1}.dll", configuration, product),
                        Target = "lib\\ARM"
                }
        );
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM/{0}/{1}.lib", configuration, product),
                        Target = "lib\\ARM"
                }
        );
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("ARM/{0}/{1}_static.lib", configuration, product),
                        Target = "lib\\ARM"
                }
        );
    }
    if (("Debug".Equals(configuration) || "RelWithDebInfo".Equals(configuration)))
    {
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("x64/{0}/{1}64.pdb", configuration, product),
                        Target = "lib\\x64"
                }
        );
        if (("v142".Equals(cmakeToolset) || "v143".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArm64EcBinary))
        {
            nuspecContents.Add(
                    new NuSpecContent
                    {
                            Source = string.Format("ARM64EC/{0}/{1}64.pdb", configuration, product),
                            Target = "lib\\ARM64EC"
                    }
            );
        }
        if (("v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
        {
            nuspecContents.Add(
                    new NuSpecContent
                    {
                            Source = string.Format("ARM64/{0}/{1}64.pdb", configuration, product),
                            Target = "lib\\ARM64"
                    }
            );
        }
        nuspecContents.Add(
                new NuSpecContent
                {
                        Source = string.Format("Win32/{0}/{1}.pdb", configuration, product),
                        Target = "lib\\Win32"
                }
        );
        if (("v140".Equals(cmakeToolset) || "v141".Equals(cmakeToolset) || "v142".Equals(cmakeToolset)) && "ON".Equals(cmakeWithArmBinary))
        {
            nuspecContents.Add(
                    new NuSpecContent
                    {
                            Source = string.Format("ARM/{0}/{1}.pdb", configuration, product),
                            Target = "lib\\ARM"
                    }
            );
        }
    }
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("../../source/{0}.h", product),
                    Target = "include"
            }
    );
    nuspecContents.Add(
            new NuSpecContent
            {
                    Source = string.Format("../../source/{0}.hpp", product),
                    Target = "include"
            }
    );

    var nuGetPackSettings = new NuGetPackSettings
    {
            Id = product + "." + cmakeToolset,
            Version = nugetPackVersion,
            Authors = new[] {"HTC"},
            Description = productDescription + " [CommitId: " + commitId + "]",
            Copyright = copyright,
            ProjectUrl = new Uri(projectUrl),
            Tags = nugetTags,
            RequireLicenseAcceptance= false,
            Files = nuspecContents.ToArray(),
            Properties = new Dictionary<string, string>
            {
                    {"Configuration", configuration}
            },
            BasePath = tempDir + Directory(configuration),
            OutputDirectory = nugetDir
    };

    NuGetPack(nuGetPackSettings);
});

Task("Publish-NuGet-Package")
    .WithCriteria(() => isReleaseBuild && !"NOTSET".Equals(nugetApiKey) && !"NOTSET".Equals(nugetSource))
    .IsDependentOn("Build-NuGet-Package")
    .Does(() =>
{
    var nugetPushVersion = semanticVersion;
    if (!isReleaseBuild)
    {
        nugetPushVersion = string.Format("{0}-CI{1}", ciVersion, revision);
    }
    Information("Publish version: {0}", nugetPushVersion);
    var package = string.Format("./dist/{0}/nuget/{1}.{2}.nupkg", configuration, product + "." + cmakeToolset, nugetPushVersion);
    NuGetPush(
            package,
            new NuGetPushSettings
            {
                    Source = nugetSource,
                    ApiKey = nugetApiKey
            }
    );
});


//////////////////////////////////////////////////////////////////////
// TASK TARGETS
//////////////////////////////////////////////////////////////////////

Task("Default")
    .IsDependentOn("Build-NuGet-Package");

//////////////////////////////////////////////////////////////////////
// EXECUTION
//////////////////////////////////////////////////////////////////////

RunTarget(target);
