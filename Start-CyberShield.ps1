$ErrorActionPreference = "Stop"
$project = $PSScriptRoot
Set-Location -LiteralPath $project
$exe = Join-Path $project "build\Release\cybershield.exe"
if (!(Test-Path -LiteralPath $exe)) {
    if (!$env:VCPKG_ROOT) { throw "Set VCPKG_ROOT to your bootstrapped vcpkg folder. See README.md." }
    $toolchain = Join-Path $env:VCPKG_ROOT "scripts\buildsystems\vcpkg.cmake"
    cmake -S backend -B build -G "Visual Studio 17 2022" -A x64 "-DCMAKE_TOOLCHAIN_FILE=$toolchain" -DVCPKG_TARGET_TRIPLET=x64-windows
    if ($LASTEXITCODE) { throw "CMake configuration failed." }
    cmake --build build --config Release --parallel 2
    if ($LASTEXITCODE) { throw "C++ build failed." }
}
Write-Host "Open http://127.0.0.1:8080 in your browser. Press Ctrl+C here to stop."
& $exe $project

