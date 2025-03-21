$PSDefaultParameterValues['Copy-Item: Confirm'] = {
	$CopyItemParameters = (Get-Command -Name Copy-Item).Parameters
	$BoundParameters = @(@(), @())
	$ScriptBlock = 'param(' +
	'[Parameter(Position = 0, ValueFromPipeline, ValueFromPipelineByPropertyName)][string[]]$Path, ' +
	'[Parameter(ValueFromPipelineByPropertyName)][Alias("PSPath", "LP")][string[]]$LiteralPath, ' +
	'[Parameter(Position = 1, ValueFromPipelineByPropertyName)][string]$Destination, ' +
	'[ref]$BoundParametersRef = [ref]$BoundParameters'
	foreach ($Key in $args[0].BoundParameters) {
		if ($Key -notin [System.Management.Automation.Internal.CommonParameters].DeclaredProperties.Name -and
			$Key -ne 'Path' -and $Key -ne 'LiteralPath' -and $Key -ne 'Destination') {
			$ScriptBlock += $CopyItemParameters[$Key].SwitchParameter ? ", [switch]`$${Key}" : ", `$${Key}"
		}
	}
	$ScriptBlock += ') process { $BoundParametersRef.Value[0] += @(, ($LiteralPath ?? $Path)); $BoundParametersRef.Value[1] += $Destination }'
	$Command = (Get-PSCallStack)[1].Position.Text -replace '(^|[|(=])\s*(Copy-Item|copy|cpi|cp)(\s+|$)', "`$1 & { ${ScriptBlock} }`$3"
	Invoke-Expression -Command $Command | Out-Null
	$Source = [string[][]]$BoundParameters[0]
	$Destination = [string[]]$BoundParameters[1]
	if ($Source.Count -ne 1 -or $Source[0].Count -ne 1 -or $Destination.Count -ne 1 -or
		$Source[0][0] -match '[*?]' -or -not (Test-Path -Path $Source[0][0])) {
		return $true
	}
	$Source = Convert-Path -Path $Source[0][0]
	$Destination = $Destination[0]
	if (-not $Destination) {
		$Destination = '.'
	}
	if (-not (Test-Path -LiteralPath $Destination)) {
		return $false
	}
	if ((Test-Path -LiteralPath $Destination -PathType Container)) {
		return (Test-Path -LiteralPath (Join-Path -Path $Destination -ChildPath (Split-Path -Path $Source -Leaf)))
	}
	return $true
}
$PSDefaultParameterValues['Remove-*: Confirm'] = $true
$PSDefaultParameterValues['Format-Table: AutoSize'] = $true
$PSDefaultParameterValues['Format-Table: Wrap'] = $true

$Global:ErrorView = 'NormalView'

Set-Alias -Name alias -Value Get-Alias
Set-Alias -Name date -Value Get-Date

function prompt {
	$PromptString = "PS `e[32m${env:USERNAME}@${env:USERDOMAIN}`e[m:`e[36m${PWD}`e[m"
	"${PromptString}$($PromptString.Length -gt $Host.UI.RawUI.WindowSize.Width * 2 / 3 ? "`n" : '')$('>' * ($NestedPromptLevel + 1)) "
}

Set-PSReadLineOption -HistorySaveStyle SaveNothing
Register-EngineEvent -SourceIdentifier PowerShell.OnIdle -Action {
	Unregister-Event -SourceIdentifier PowerShell.OnIdle
	$Global:LastWorkingDirectory = Get-Location
	New-Item -Path Function:\InitialPrompt -Value (Get-Command -Name prompt).Definition -Force
	Set-Item -Path Function:\prompt -Value {
		$PSReturn = $?
		$Global:HISTFILE = (Get-PSReadLineOption).HistorySavePath
		$Global:HISTLOG = $Global:HISTFILE -replace '^(.*\.log(?=$)|.*?)(\.[^./\\]*)?$', '$1.log'
		if ((Get-PSReadLineOption).HistorySaveStyle -ne [Microsoft.PowerShell.HistorySaveStyle]::SaveNothing) {
			$NewHistoryEntry = Get-History -Count 1
			if (($Script:HistoryEntryId ?? 0) -lt ($NewHistoryEntry.Id ?? 0)) {
				$Script:HistoryEntryId = $NewHistoryEntry.Id
				"Command  : $($NewHistoryEntry.CommandLine)`n" +
				"Directory: $($Global:LastWorkingDirectory)`n" +
				"Time     : $($NewHistoryEntry.StartExecutionTime) - $($NewHistoryEntry.EndExecutionTime)`n" +
				"Status   : $($NewHistoryEntry.ExecutionStatus)`n" +
				"PSReturn : ${PSReturn}`n" +
				"ExitCode : ${LASTEXITCODE}`n" | Out-File -Path $Global:HISTLOG -Append
			}
		}
		'-' * $Host.UI.RawUI.WindowSize.Width | Out-Host
		$Global:LastWorkingDirectory = Get-Location
		InitialPrompt
	}
} | Out-Null

function bg([scriptblock]$ScriptBlock) {
	$Command = "Set-Location -Path '${PWD}'; ${ScriptBlock}"
	$EncodedCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))
	Start-Process -FilePath pwsh -ArgumentList "-EncodedCommand ${EncodedCommand}"
}

function sudo {
	[CmdletBinding()]

	param(
		[Parameter(Mandatory, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[scriptblock]$ScriptBlock,

		[switch]$AsTask,
		[switch]$PreserveEnvironment
	)

	dynamicparam {
		$DynamicParameters = [System.Management.Automation.RuntimeDefinedParameterDictionary]::new()
		$AttributeCollection = [System.Collections.ObjectModel.Collection[System.Attribute]]::new()
		$ParameterAttributes = [System.Management.Automation.ParameterAttribute]@{ Mandatory = $false }
		$AttributeCollection.Add($ParameterAttributes)
		if ($AsTask) {
			$ValidationAttribute = [System.Management.Automation.ValidateScriptAttribute]::new({
					try {
						[System.Security.Principal.NTAccount]::new($_).Translate([System.Security.Principal.SecurityIdentifier])
						return $true
					}
					catch {
					}
					try {
						[System.Security.Principal.SecurityIdentifier]::new($_)
						return $true
					}
					catch {
						return $false
					}
				})
			$AttributeCollection.Add($ValidationAttribute)
			$RunAsParameter = [System.Management.Automation.RuntimeDefinedParameter]::new('RunAs', [string], $AttributeCollection)
			$DynamicParameters.Add('RunAs', $RunAsParameter)
		}
		else {
			$InteractiveParameter = [System.Management.Automation.RuntimeDefinedParameter]::new('Interactive', [switch], $AttributeCollection)
			$DynamicParameters.Add('Interactive', $InteractiveParameter)
		}
		return $DynamicParameters
	}

	process {
		$SudoId = New-Guid
		$Command = "Set-Location -LiteralPath '${PWD}'`n"

		if ($PreserveEnvironment) {
			$EnvFile = "${env:TMP}\env-${SudoId}.xml"
			$VarFile = "${env:TMP}\var-${SudoId}.xml"
			$FnFile = "${env:TMP}\fn-${SudoId}.xml"
			Get-ChildItem -Path Env:\ | Export-Clixml -Path $EnvFile
			Get-Variable | Where-Object -FilterScript {
				-not ($_.Options -band [System.Management.Automation.ScopedItemOptions]::ReadOnly) -and
				-not ($_.Options -band [System.Management.Automation.ScopedItemOptions]::Constant) -and
				$_.Name -ne 'PSBoundParameters'
			} | Export-Clixml -Path $VarFile
			Get-ChildItem -Path Function:\ | Export-Clixml -Path $FnFile
			$Command +=
			"Import-Clixml -Path '${EnvFile}' | ForEach-Object -Process { Set-Item -Path Env:\`$(`$_.Name) -Value `$_.Value }`n" +
			"Import-Clixml -Path '${VarFile}' | Where-Object -FilterScript { `$_.Value?.GetType() -ne [psobject] } | ForEach-Object -Process { Set-Variable -Name `$_.Name -Value `$_.Value }`n" +
			"Import-Clixml -Path '${FnFile}' | ForEach-Object -Process { Set-Item -Path `$_.PSPath -Value `$_.Definition }`n"
		}

		$Interactive = $PSBoundParameters['Interactive'].IsPresent ?? $false
		if ($Interactive) {
			$Command += $ScriptBlock
		}
		else {
			$Python = (Get-Command -Name python).Source
			$TcpRecv = (Get-Command -Name tcp-recv.py).Source
			$TcpSend = (Get-Command -Name tcp-send.py).Source
			$Command += "& { ${ScriptBlock} } 2>&1 | & '${Python}' '${TcpSend}' 20316"
		}
		$EncodedCommand = [System.Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes($Command))

		if ($AsTask) {
			$TaskName = "Sudo_{${SudoId}}"
			$User = $PSBoundParameters['RunAs'] ?? 'NT AUTHORITY\SYSTEM'
			$Action = New-ScheduledTaskAction -Execute (Get-Command -Name pwsh).Source -Argument "-EncodedCommand ${EncodedCommand}"
			$Settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries
			Register-ScheduledTask -TaskName $TaskName -Action $Action -Settings $Settings -User $User -RunLevel Highest | Start-ScheduledTask
			python $TcpRecv 20316
			Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
		}
		else {
			Start-Process -FilePath pwsh -ArgumentList '-EncodedCommand', $EncodedCommand -Verb RunAs -WindowStyle ($Interactive ? 'Normal' : 'Hidden') -Wait:$Interactive
			if (-not $Interactive) {
				python $TcpRecv 20316
			}
		}

		if ($PreserveEnvironment) {
			Remove-Item -Path $EnvFile, $VarFile, $FnFile -Confirm:$false
		}
	}
}

function New-Shortcut {
	[CmdletBinding(DefaultParameterSetName = 'Path', SupportsShouldProcess)]
	[OutputType([System.__ComObject])]

	param(
		[Parameter(Mandatory, Position = 0, ParameterSetName = 'Path', ValueFromPipelineByPropertyName)]
		[Alias('Path', 'FullName', 'Name')]
		[ValidateNotNullOrEmpty()]
		[string]$TargetPath,
		[Parameter(Mandatory, Position = 0, ParameterSetName = 'Url', ValueFromPipelineByPropertyName)]
		[Alias('Url', 'Uri')]
		[ValidateNotNullOrEmpty()]
		[uri]$TargetUrl,

		[Parameter(Position = 1, ParameterSetName = 'Path')]
		[Parameter(Mandatory, Position = 1, ParameterSetName = 'Url')]
		[ValidateNotNullOrEmpty()]
		[string]$ShortcutPath,

		[Parameter(ParameterSetName = 'Path')]
		[string]$Arguments,
		[Parameter(ParameterSetName = 'Path')]
		[string]$Description,
		[Parameter(ParameterSetName = 'Path')]
		[Alias('ha')]
		[switch]$HotkeyAlt,
		[Parameter(ParameterSetName = 'Path')]
		[Alias('hc')]
		[switch]$HotkeyCtrl,
		[Parameter(ParameterSetName = 'Path')]
		[Alias('hs')]
		[switch]$HotkeyShift,
		[Parameter(ParameterSetName = 'Path')]
		[Alias('hk')]
		[ValidateSet('A', 'B', 'C', 'D', 'E', 'F', 'G', 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X', 'Y', 'Z',
			'Up', 'Down', 'Left', 'Right', 'Home', 'End', 'Insert', 'Delete',
			'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12')]
		[string]$HotkeyKey,
		[Parameter(ParameterSetName = 'Path')]
		[string]$IconLocationPath,
		[Parameter(ParameterSetName = 'Path')]
		[int]$IconLocationIndex = 0,
		[Parameter(ParameterSetName = 'Path')]
		[ValidateSet('Normal', 'Maximized', 'Minimized')]
		[string]$WindowStyle = 'Normal',
		[Parameter(ParameterSetName = 'Path')]
		[string]$WorkingDirectory
	)

	$ErrorActionPreference = 'Stop'

	if ($PSCmdlet.ParameterSetName -eq 'Path') {
		if (-not (Test-Path -Path $TargetPath)) {
			Write-Error -Exception ([System.Management.Automation.ItemNotFoundException]::new()) -Message "TargetPath '${TargetPath}' does not exist." -Category ObjectNotFound -ErrorId 'PathNotFound' -TargetObject $TargetPath -CategoryActivity 'New-Shortcut'
		}
		$Target = Convert-Path -Path $TargetPath
		if (-not $ShortcutPath) {
			$ShortcutPath = (Split-Path -Path $TargetPath -Leaf) + '.lnk'
		}
		elseif ((Test-Path -Path $ShortcutPath -PathType Container)) {
			$ShortcutPath = Join-Path -Path $ShortcutPath -ChildPath ((Split-Path -Path $TargetPath -Leaf) + '.lnk')
		}
		elseif (-not $ShortcutPath.EndsWith('.lnk')) {
			$ShortcutPath += '.lnk'
		}
	}
	else {
		$Target = [string]$TargetUrl
		if (-not $ShortcutPath.EndsWith('.url')) {
			$ShortcutPath += '.url'
		}
	}
	if (-not [System.IO.Path]::IsPathRooted($ShortcutPath)) {
		$ShortcutPath = Join-Path -Path $PWD -ChildPath $ShortcutPath
	}
	if (-not (Test-Path -Path (Split-Path -Path $ShortcutPath -Parent) -PathType Container)) {
		Write-Error -Exception ([System.ArgumentException]::new()) -Message "ShortcutPath '${ShortcutPath}' is not a valid path." -Category InvalidArgument -ErrorId 'InvalidPath' -TargetObject $ShortcutPath -CategoryActivity 'New-Shortcut'
	}

	$WScriptShell = New-Object -ComObject WScript.Shell
	$Shortcut = $WScriptShell.CreateShortcut($ShortcutPath)

	$Shortcut.TargetPath = $Target
	if ($PSCmdlet.ParameterSetName -eq 'Path') {
		if (($HotkeyAlt -or $HotkeyCtrl) -and (-not $HotkeyShift) -and (-not $HotkeyKey)) {
			Write-Error -Message 'Hotkey Alt/Ctrl/Alt+Ctrl cannot be used alone.' -Category InvalidArgument -Exception ([System.Management.Automation.ParameterBindingException]::new())
		}

		$Shortcut.Arguments = $Arguments
		$Shortcut.Description = $Description
		$Shortcut.Hotkey = $(if ($HotkeyAlt) { 'Alt' } if ($HotkeyCtrl) { 'Ctrl' } if ($HotkeyShift) { 'Shift' } if ($HotkeyKey) { $HotkeyKey }) -join '+'
		$Shortcut.IconLocation = "${IconLocationPath},${IconLocationIndex}"
		$Shortcut.WindowStyle = @{ Normal = 1; Maximized = 3; Minimized = 7 }[$WindowStyle]
		$Shortcut.WorkingDirectory = $WorkingDirectory
	}

	if ($PSCmdlet.ShouldProcess("Item: ${Target} Destination: ${ShortcutPath}", 'Create Shortcut')) {
		$Shortcut.Save()
	}

	return $Shortcut
}

class ArgumentToEncodingTransformationAttribute : System.Management.Automation.ArgumentTransformationAttribute {
	hidden static $Map = @{
		ansi             = [System.Text.Encoding]::GetEncoding([cultureinfo]::CurrentCulture.TextInfo.ANSICodePage);
		ascii            = [System.Text.Encoding]::ASCII;
		bigendianunicode = [System.Text.Encoding]::BigEndianUnicode;
		bigendianutf32   = [System.Text.UTF32Encoding]::new($true, $true);
		oem              = [System.Text.Encoding]::Default;
		unicode          = [System.Text.Encoding]::Unicode;
		utf7             = [System.Text.Encoding]::UTF7;
		utf8             = [System.Text.Encoding]::UTF8;
		utf8BOM          = [System.Text.Encoding]::UTF8;
		utf8NoBOM        = [System.Text.UTF8Encoding]::new($false);
		utf32            = [System.Text.Encoding]::UTF32
	}

	[System.Object] Transform([System.Management.Automation.EngineIntrinsics]$EngineIntrinsics, [System.Object]$Value) {
		if ($Value -is [System.Text.Encoding]) {
			return $Value
		}

		try {
			return [ArgumentToEncodingTransformationAttribute]::Map[$Value] ?? [System.Text.Encoding]::GetEncoding($Value)
		}
		catch {
			throw [System.Management.Automation.ArgumentTransformationMetadataException]::new("Invalid encoding: '${Value}'")
		}
	}
}

function slspp {
	[CmdletBinding(DefaultParameterSetName = 'File')]
	[OutputType([Microsoft.PowerShell.Commands.MatchInfo], [string], [bool], [void])]

	param(
		[Parameter(Mandatory, Position = 0)]
		[ValidateNotNullOrEmpty()]
		[string[]]$Pattern,

		[Parameter(Mandatory, Position = 1, ParameterSetName = 'File', ValueFromPipelineByPropertyName)]
		[ValidateNotNullOrEmpty()]
		[string[]]$Path,
		[Parameter(Mandatory, ParameterSetName = 'LiteralFile', ValueFromPipelineByPropertyName)]
		[Alias('PSPath')]
		[ValidateNotNullOrEmpty()]
		[string[]]$LiteralPath,
		[Parameter(Mandatory, ParameterSetName = 'Object', ValueFromPipeline)]
		[ValidateNotNullOrEmpty()]
		[psobject]$InputObject,

		[switch]$IgnoreCase,
		[switch]$List,
		[switch]$NotMatch,
		[switch]$Quiet,
		[switch]$Raw,
		[switch]$SimpleMatch,

		[ValidateCount(1, 2)]
		[ValidateNotNullOrEmpty()]
		[ValidateRange(0, [int]::MaxValue)]
		[int[]]$Context,

		[ArgumentCompletions('ansi', 'ascii', 'bigendianunicode', 'bigendianutf32', 'oem', 'unicode', 'utf7', 'utf8', 'utf8BOM', 'utf8NoBOM', 'utf32')]
		[ArgumentToEncodingTransformation()]
		[System.Text.Encoding]$Encoding = 'utf8NoBOM',

		[ValidateNotNullOrEmpty()]
		[string[]]$Exclude,
		[ValidateNotNullOrEmpty()]
		[string[]]$Include
	)

	$PSBoundParameters['AllMatches'] = $true
	$PSBoundParameters['CaseSensitive'] = -not $IgnoreCase
	$PSBoundParameters.Remove('IgnoreCase') | Out-Null
	if ($input) {
		$PSBoundParameters.Remove('InputObject') | Out-Null
		$MatchResult = $input | Select-String @PSBoundParameters
	}
	else {
		$MatchResult = Select-String @PSBoundParameters
	}

	if ($Raw -or $Quiet -or $MyInvocation.PipelinePosition -ne $MyInvocation.PipelineLength) {
		return $MatchResult
	}

	$RegExps = @()
	foreach ($RegExp in $Pattern) {
		if ($SimpleMatch) {
			$RegExp = [regex]::Escape($RegExp)
		}
		if ($IgnoreCase) {
			$RegExp = "(?i)${RegExp}"
		}
		$RegExps += $RegExp
	}
	$RegExps = $RegExps -join '|'

	$FormatString = "`e[35m{0}`e[36m{1}`e[32m{2}`e[36m{1}`e[m{3}"
	$ReplaceString = "`e[31;1m`$0`e[m"
	$ShowContext = $Context -and ($Context[0] -gt 0 -or ($Context.Length -eq 2 -and $Context[1] -gt 0))
	if ($ShowContext) {
		$MatchSign = '> '
	}
	else {
		$MatchSign = ''
	}

	for ($i = 0; $i -lt $MatchResult.Length; $i++) {
		$MatchEntry = $MatchResult[$i]

		if ($i -eq 0 -or $MatchEntry.Path -ne $MatchResult[$i - 1].Path) {
			$LineNumber = 1
		}

		if ($ShowContext) {
			$PreContext = $MatchEntry.Context.PreContext
			$PreContextFirstLine = $MatchEntry.LineNumber - $PreContext.Length
			if (($i -gt 0 -and $LineNumber -eq 1) -or ($LineNumber -gt 1 -and $LineNumber -lt $PreContextFirstLine)) {
				"`e[36m--`e[m" | Out-Host
			}
			$LineNumber = [System.Math]::Max($LineNumber, $PreContextFirstLine)
			$Index = $LineNumber - $PreContextFirstLine
			while ($LineNumber -lt $MatchEntry.LineNumber) {
				$Line = $PreContext[$Index++] -creplace $RegExps, $ReplaceString
				"  ${FormatString}" -f $MatchEntry.Path, '-', $LineNumber++, $Line | Out-Host
			}
		}

		$Line = $MatchEntry.Line -creplace $RegExps, $ReplaceString
		"${MatchSign}${FormatString}" -f $MatchEntry.Path, ':', $MatchEntry.LineNumber, $Line | Out-Host
		$LineNumber = $MatchEntry.LineNumber + 1

		if ($ShowContext) {
			$PostContext = $MatchEntry.Context.PostContext
			$Index = 0
			$MaxIndex = $PostContext.Length
			if ($i -lt ($MatchResult.Length - 1) -and $MatchEntry.Path -eq $MatchResult[$i + 1].Path) {
				$MaxIndex = [System.Math]::Min($MaxIndex, $MatchResult[$i + 1].LineNumber - $MatchEntry.LineNumber - 1)
			}
			while ($Index -lt $MaxIndex) {
				$Line = $PostContext[$Index++] -creplace $RegExps, $ReplaceString
				"  ${FormatString}" -f $MatchEntry.Path, '-', $LineNumber++, $Line | Out-Host
			}
		}
	}
}
