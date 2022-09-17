#
# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
# 
#   http://www.apache.org/licenses/LICENSE-2.0
# 
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
#

$ErrorActionPreference = "stop"

# Use TLS 1.2 for all downloads.
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

${env:__BUILD_ENV_INITIALIZED} = "1"

#------------------------------------------------------------------------------
# Find MSBuild and add to PATH
#
# NB. Search ProgramFiles only since we need VS2022+ for .NET 6.
#------------------------------------------------------------------------------


$MsBuildCandidates = `
    "${Env:ProgramFiles}\Microsoft Visual Studio\*\*\MSBuild\*\bin\msbuild.exe",
    "c:\VS\MSBuild\Current\Bin\"

$Msbuild = $MsBuildCandidates | Resolve-Path  -ErrorAction Ignore | Select-Object -ExpandProperty Path -Last 1
if ($Msbuild)
{
	$MsbuildDir = (Split-Path $Msbuild -Parent)
	$env:Path += ";$MsbuildDir"
}
else
{
	Write-Host "Could not find msbuild" -ForegroundColor Red
	exit 1
}

#------------------------------------------------------------------------------
# Find nmake and add to PATH
#------------------------------------------------------------------------------

$NmakeCandidates = `
    "${Env:ProgramFiles}\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx86\*\nmake.exe",
    "${Env:ProgramFiles(x86)}\Microsoft Visual Studio\*\*\VC\Tools\MSVC\*\bin\Hostx86\*\nmake.exe",
    "c:\VS\VC\Tools\MSVC\*\bin\Hostx86\*\nmake.exe"
$Nmake = $NmakeCandidates | Resolve-Path  -ErrorAction Ignore | Select-Object -ExpandProperty Path -Last 1
if ($Nmake)
{
	$NMakeDir = (Split-Path $NMake -Parent)
	$env:Path += ";$NMakeDir"
}
else
{
	Write-Host "Could not find nmake" -ForegroundColor Red
	exit 1
}

#------------------------------------------------------------------------------
# Find nuget and add to PATH
#------------------------------------------------------------------------------

if ((Get-Command "nuget.exe" -ErrorAction SilentlyContinue) -eq $null) 
{
	$NugetDownloadUrl = "https://dist.nuget.org/win-x86-commandline/latest/nuget.exe"

	New-Item -ItemType Directory -Force "${PSScriptRoot}\.tools" | Out-Null
	$Nuget = "${PSScriptRoot}\.tools\nuget.exe"
	(New-Object System.Net.WebClient).DownloadFile($NugetDownloadUrl, $Nuget)
	
	$env:Path += ";${PSScriptRoot}\.tools"
}

#------------------------------------------------------------------------------
# Restore packages and make them available in the environment
#------------------------------------------------------------------------------

if ((Test-Path "*.sln") -and !$args.Contains("clean"))
{
    #
    # Restore packages for solution.
    #
	& $Nmake restore
	if ($LastExitCode -ne 0)
	{
		exit $LastExitCode
	}

	#
	# Add environment variables indicating package versions, for example
	# $env:Google_Apis_Auth = 1.2.3
	#
	Select-Xml .\Jpki\Jpki.csproj -XPath '//PackageReference' `
		| Select-Object -ExpandProperty Node `
		| ForEach-Object { New-Item -Name $_.Include.Replace(".", "_") -Value $_.Version -ItemType Variable -Path Env: -Force }

	#
	# Add all tools to PATH.
	#
	
	$ToolsDirectories = ('.\Jpki\Jpki.csproj' | ForEach-Object { 
		Select-Xml $_ -XPath '//PackageReference' `
			| Select-Object -ExpandProperty Node `
			| ForEach-Object { 
				Get-ChildItem -Directory -Recurse "$($Env:HOMEDRIVE)$($Env:HOMEPATH)\.nuget\packages\$($_.Include)" `
					| Where-Object {$_.Name.EndsWith("tools") -or $_.FullName.Contains("tools\net4") } `
					| Select-Object -ExpandProperty FullName
			}
		})

	$env:Path += ";" + ($ToolsDirectories -join ";")
}

Write-Host "PATH: ${Env:PATH}" -ForegroundColor Yellow

#------------------------------------------------------------------------------
# Run nmake.
#------------------------------------------------------------------------------

& $Nmake $args

if ($LastExitCode -ne 0)
{
    exit $LastExitCode
}
