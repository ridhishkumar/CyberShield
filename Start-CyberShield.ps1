$ErrorActionPreference = "Stop"
$project = $PSScriptRoot
Set-Location -LiteralPath $project
$build = Join-Path $project "build\source"
$exe = Join-Path $build "Release\cybershield.exe"
$sourceFiles = @((Join-Path $project "backend\CMakeLists.txt"),
                 (Join-Path $project "backend\vcpkg.json"))
$sourceDirs = @((Join-Path $project "backend\src"),
                (Join-Path $project "backend\include"),
                (Join-Path $project "backend\tests"))
foreach ($sourceDir in $sourceDirs) {
    $sourceFiles += @(Get-ChildItem -LiteralPath $sourceDir -Recurse -File -ErrorAction SilentlyContinue |
        ForEach-Object { $_.FullName })
}
$latestSource = ($sourceFiles |
    ForEach-Object { (Get-Item -LiteralPath $_).LastWriteTimeUtc } |
    Measure-Object -Maximum).Maximum
$needsBuild = $true
if (Test-Path -LiteralPath $exe) {
    $needsBuild = (Get-Item -LiteralPath $exe).LastWriteTimeUtc -lt $latestSource
}
if ($needsBuild) {
    if (!$env:VCPKG_ROOT) { throw "Set VCPKG_ROOT to your bootstrapped vcpkg folder. See README.md." }
    $toolchain = Join-Path $env:VCPKG_ROOT "scripts\buildsystems\vcpkg.cmake"
    cmake -S backend -B $build -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$toolchain" -DVCPKG_TARGET_TRIPLET=x64-windows -DVCPKG_MANIFEST_MODE=ON
    if ($LASTEXITCODE) { throw "CMake configuration failed." }
    cmake --build $build --config Release --target cybershield --parallel 2
    if ($LASTEXITCODE) { throw "C++ build failed." }
}
Write-Host "Open http://127.0.0.1:8080 in your browser. Press Ctrl+C here to stop."
& $exe $project

