#
# Copyright 2023 Johannes Passing
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

#------------------------------------------------------------------------------
# Basic configuration
#------------------------------------------------------------------------------

PRODUCT_VERSION = 1.0
CONFIGURATION = Release
PLATFORM=Any CPU
PLATFORM_FOLDER=AnyCPU

!if ( "$(GITHUB_RUN_NUMBER)" != "" ) 
BUILD_NUMBER = $(GITHUB_RUN_NUMBER)
!else
BUILD_NUMBER = 1
!endif

BINARY_VERSION = $(PRODUCT_VERSION).$(BUILD_NUMBER)

ASSEMBLY_DIR = Jpki\bin\$(CONFIGURATION)
MAIN_ASSEMBLY = $(ASSEMBLY_DIR)\Jpki.dll

TARGET_FRAMEWORK = net47
NUNIT_ASSEMBLIES = \
	Jpki.Extensions.Test\bin\$(PLATFORM_FOLDER)\$(CONFIGURATION)\$(TARGET_FRAMEWORK)\Jpki.Extensions.Test.dll \
	Jpki.Fido.Test\bin\$(PLATFORM_FOLDER)\$(CONFIGURATION)\$(TARGET_FRAMEWORK)\Jpki.Fido.Test.dll
NUNIT_COVERAGE_FILTER = \
	+[Jpki.Extensions]* \
	+[Jpki.Fido]* \

NUGET_PACKAGEDIR=$(HOMEPATH)\.nuget\packages
IISEXPRESS=$(PROGRAMFILES)\IIS Express\iisexpress.exe
    
#------------------------------------------------------------------------------
# Output targets
#------------------------------------------------------------------------------

default: test $(PACKED_ASSEMBLY)

$(MAIN_ASSEMBLY):
	@echo "========================================================"
	@echo "=== Building solution                                ==="
	@echo "========================================================"

	msbuild /t:Rebuild "/p:Configuration=$(CONFIGURATION);Platform=$(PLATFORM);AssemblyVersionNumber=$(BINARY_VERSION);Version=$(BINARY_VERSION)"
	
restore:
	@echo "========================================================"
	@echo "=== Restoring nuget packages                         ==="
	@echo "========================================================"

	nuget restore

build: $(MAIN_ASSEMBLY)

test-net: $(MAIN_ASSEMBLY)
	@echo "========================================================"
	@echo "=== Testing solution (.NET)                          ==="
	@echo "========================================================"

	dotnet test \
		--no-build \
		--configuration $(CONFIGURATION) \
		--filter "TestCategory!=RequiresHumanInteraction""

# NB. The OpenCover version must match the version of the CLR installed
test-netfx: $(MAIN_ASSEMBLY)
	@echo "========================================================"
	@echo "=== Testing solution (.NET Framework, with coverage) ==="
	@echo "========================================================"

	OpenCover.Console.exe \
		-register:user \
		-returntargetcode \
		-target:nunit3-console.exe \
		"-targetargs:$(NUNIT_ASSEMBLIES) --agents=1 --where "cat!=RequiresHumanInteraction"" \
		-filter:"$(NUNIT_COVERAGE_FILTER)" \
		"-excludebyattribute:*CompilerGenerated*" \
		-output:opencovertests.xml

	ReportGenerator.exe \
		-reports:opencovertests.xml \
		-targetdir:coveragereport \
		-reporttypes:HTML
	del $(MAKEDIR)\*.log

test: test-net test-netfx

clean:
	@echo "========================================================"
	@echo "=== Building solution                                ==="
	@echo "========================================================"

	msbuild /t:Clean "/p:Configuration=$(CONFIGURATION);Platform=$(PLATFORM)"
	
serve-site:
	"$(IISEXPRESS)" /path:$(MAKEDIR)\site