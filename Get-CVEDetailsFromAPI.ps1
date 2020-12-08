<#
.SYNOPSIS
   Script to get CVE vulnerability details.
.DESCRIPTION
   Script that receives list of CVE IDs, gets all their details from the nvd.nist.gov API and saves them to a CSV file.
.EXAMPLE
   Get-Content .\CVEs.txt | .\Get-CVEDetailsFromAPI.ps1
   Assuming CVEs.txt contains one CVE per line, reads the file and sends it to the script.
.EXAMPLE
   .\Get-CVEDetailsFromAPI.ps1 -CVEs "CVE-2019-2988","CVE-2015-0458"
   Query one or more CVEs directly.
.EXAMPLE
   .\Get-CVEDetailsFromAPI.ps1 -Path .\CVEs.txt
   Query all the CVEs contained in CVEs.txt.
.LINK
   More information about this API can be found at:
   https://csrc.nist.gov/CSRC/media/Projects/National-Vulnerability-Database/documents/web%20service%20documentation/Automation%20Support%20for%20CVE%20Retrieval.pdf
.NOTES
   Author:
   Luis Vargas (https://www.linkedin.com/in/vluis)
#>
[CmdletBinding()]
param (
    # Receives one or more CVEs, either directly or through the pipeline.
    [Parameter(Mandatory = $true,
        ValueFromPipeline = $true,
        Position = 0,
        ParameterSetName = 'From string array')]
    [ValidatePattern("^CVE-\d{4}-(0\d{3}|[1-9]\d{3,})$")]
    [String[]]
    $CVEs,

    # Accepts the path of a file that should contain one CVE per line.
    [Parameter(Mandatory = $true,
        Position = 0,
        ParameterSetName = 'From file')]
    [ValidateScript({ Test-Path $_ })]
    $Path,

    # Defines the delay in seconds between each API request. The default value is 3.
    [Parameter(Mandatory = $false,
        Position = 1)]
    [ValidateRange(0, [int]::MaxValue)]
    $Delay = 3
)

Begin {
    #If the Path parameter was set, the correct file path is resolved and its CVEs are stored in a variable.
    if ($Path) {
        $Path = Resolve-Path $Path
        $CVEs = [System.IO.File]::ReadAllLines($Path.Path)
    }

    #The path where this script is located.
    $CurrentPath = Split-Path -Parent $MyInvocation.MyCommand.Path

    #Variables to iterate and show the progress bar.
    $i = 1
    $Total = $CVEs.Length
    $PercentComplete = -1

    #The array where all the rows will be stored.
    $Data = @()

    #The report columns.
    $Columns = @(
        'CVE'
        'CVSS3_Vector'
        'CVSS3_AttackVector'
        'CVSS3_AttackComplexity'
        'CVSS3_PrivilegesRequired'
        'CVSS3_UserInteraction'
        'CVSS3_Scope'
        'CVSS3_Confidentiality'
        'CVSS3_Integrity'
        'CVSS3_Availability'
        'CVSS3_BaseScore'
        'CVSS3_BaseSeverity'
        'CVSS3_ExploitabilityScore'
        'CVSS3_ImpactScore'
        'CVSS2_Vector'
        'CVSS2_AccessVector'
        'CVSS2_AccessComplexity'
        'CVSS2_Authentication'
        'CVSS2_Confidentiality'
        'CVSS2_Integrity'
        'CVSS2_Availability'
        'CVSS2_BaseScore'
        'CVSS2_Severity'
        'CVSS2_ExploitabilityScore'
        'CVSS2_ImpactScore'
        'CVSS2_acInsufInfo'
        'CVSS2_ObtainAllPrivilege'
        'CVSS2_ObtainUserPrivilege'
        'CVSS2_ObtainOtherPrivilege'
        'CVSS2_UserInteractionRequired'
        'PublishedDate'
        'LastModifiedDate'
    )

    #The API request headers.
    $Headers = @{
        "X-Requested-With" = "PowerShell"
    }
}

Process {
    foreach ($CVE in $CVEs) {
        if ($Total) {
            $Status = "CVE $i of $Total"
            $PercentComplete = $i / $Total * 100
        }
        else {
            #If the CVEs are being received through the pipeline we will not know the total.
            $Status = "CVE $i of unknown"
        }

        #The Write-Progress parameters.
        $ProgressOptions = @{
            Activity        = "Querying the API for $CVE"
            Status          = $Status
            PercentComplete = $PercentComplete
        }

        #Used to show a progress bar.
        Write-Progress @ProgressOptions

        #A 'row' of data with the required properties (columns) is created, and the CVE ID is assigned to it.
        $Row = "" | Select-Object $Columns
        $Row.CVE = $CVE

        #The API request is made.
        $Response = Invoke-RestMethod "https://services.nvd.nist.gov/rest/json/cve/1.0/$CVE" -Headers $Headers

        #The first CVE item is stored in the $CVEInfo variable for ease of use.
        $CVEInfo = $Response.result.CVE_Items[0]

        #If CVSS3 info is found, its properties get stored in the data row.
        if ($CVEInfo.impact.baseMetricV3) {
            $Row.CVSS3_Vector = $CVEInfo.impact.baseMetricV3.cvssV3.vectorString
            $Row.CVSS3_AttackVector = $CVEInfo.impact.baseMetricV3.cvssV3.attackVector
            $Row.CVSS3_AttackComplexity = $CVEInfo.impact.baseMetricV3.cvssV3.attackComplexity
            $Row.CVSS3_PrivilegesRequired = $CVEInfo.impact.baseMetricV3.cvssV3.privilegesRequired
            $Row.CVSS3_UserInteraction = $CVEInfo.impact.baseMetricV3.cvssV3.userInteraction
            $Row.CVSS3_Scope = $CVEInfo.impact.baseMetricV3.cvssV3.scope
            $Row.CVSS3_Confidentiality = $CVEInfo.impact.baseMetricV3.cvssV3.confidentialityImpact
            $Row.CVSS3_Integrity = $CVEInfo.impact.baseMetricV3.cvssV3.integrityImpact
            $Row.CVSS3_Availability = $CVEInfo.impact.baseMetricV3.cvssV3.availabilityImpact
            $Row.CVSS3_BaseScore = $CVEInfo.impact.baseMetricV3.cvssV3.baseScore
            $Row.CVSS3_BaseSeverity = $CVEInfo.impact.baseMetricV3.cvssV3.baseSeverity
            $Row.CVSS3_ExploitabilityScore = $CVEInfo.impact.baseMetricV3.exploitabilityScore
            $Row.CVSS3_ImpactScore = $CVEInfo.impact.baseMetricV3.impactScore
        }

        #If CVSS2 info is found, its properties get stored in the data row.
        if ($CVEInfo.impact.baseMetricV2) {
            $Row.CVSS2_Vector = $CVEInfo.impact.baseMetricV2.cvssV2.vectorString
            $Row.CVSS2_AccessVector = $CVEInfo.impact.baseMetricV2.cvssV2.accessVector
            $Row.CVSS2_AccessComplexity = $CVEInfo.impact.baseMetricV2.cvssV2.accessComplexity
            $Row.CVSS2_Authentication = $CVEInfo.impact.baseMetricV2.cvssV2.authentication
            $Row.CVSS2_Confidentiality = $CVEInfo.impact.baseMetricV2.cvssV2.confidentialityImpact
            $Row.CVSS2_Integrity = $CVEInfo.impact.baseMetricV2.cvssV2.integrityImpact
            $Row.CVSS2_Availability = $CVEInfo.impact.baseMetricV2.cvssV2.availabilityImpact
            $Row.CVSS2_BaseScore = $CVEInfo.impact.baseMetricV2.cvssV2.baseScore
            $Row.CVSS2_Severity = $CVEInfo.impact.baseMetricV2.severity
            $Row.CVSS2_ExploitabilityScore = $CVEInfo.impact.baseMetricV2.exploitabilityScore
            $Row.CVSS2_ImpactScore = $CVEInfo.impact.baseMetricV2.impactScore
            $Row.CVSS2_acInsufInfo = $CVEInfo.impact.baseMetricV2.acInsufInfo
            $Row.CVSS2_ObtainAllPrivilege = $CVEInfo.impact.baseMetricV2.obtainAllPrivilege
            $Row.CVSS2_ObtainUserPrivilege = $CVEInfo.impact.baseMetricV2.obtainUserPrivilege
            $Row.CVSS2_ObtainOtherPrivilege = $CVEInfo.impact.baseMetricV2.obtainOtherPrivilege
            $Row.CVSS2_UserInteractionRequired = $CVEInfo.impact.baseMetricV2.userInteractionRequired
        }

        #The published and last modified dates get stored in the data row.
        $Row.PublishedDate = $CVEInfo.publishedDate
        $Row.LastModifiedDate = $CVEInfo.lastModifiedDate

        #The row is copied into the data array.
        $Data += $Row.PSObject.Copy()
        $i++

        #It is required to sleep between requests to avoid overwhelming the API and get blocked by it.
        Start-Sleep $Delay
    }
}

End {
    #The data array is piped into the Export-Csv cmdlet, and the CSV report is saved to the same location where the script is.
    $Data | Export-Csv -Path "$CurrentPath\CVEDetails_$(Get-Date -Format 'yyyy-MM-dd_HH.mm.ss').csv" -Force -NoTypeInformation
}