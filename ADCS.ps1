function Get-RootCA
{
    $DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
    $BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName
    $RootCA =  Get-DomainObject -SearchBase ("CN=Certification Authorities," + $BasePath) -LDAPFilter "(objectclass=certificationAuthority)"
    $RootCA
}

function Get-EnterpriseCA
{
    $DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
    $BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName
    $EnterpriseCA = Get-DomainObject -SearchBase ("CN=Enrollment Services," + $BasePath) -LDAPFilter "(objectclass=pKIEnrollmentService)"
    $EnterpriseCA
}

function Convert-ADCSPrivateKeyFlag
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Flag
    )

# Based on 2.27 msPKI-Private-Key-Flag Attribute
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/f6122d87-b999-4b92-bff8-f465e8949667

$Result = @()

$BitFlag =  [convert]::ToString($Flag,2).padleft(32,'0')

if($BitFlag.Substring(31,1) -eq '1')
{
    $Result += "CT_FLAG_REQUIRE_PRIVATE_KEY_ARCHIVAL"
}

if($BitFlag.Substring(27,1) -eq '1')
{
    $Result += "CT_FLAG_EXPORTABLE_KEY"
}

if($BitFlag.Substring(26,1) -eq '1')
{
    $Result += "CT_FLAG_STRONG_KEY_PROTECTION_REQUIRED"
}

if($BitFlag.Substring(25,1) -eq '1')
{
    $Result += "CT_FLAG_REQUIRE_ALTERNATE_SIGNATURE_ALGORITHM"
}

if($BitFlag.Substring(24,1) -eq '1')
{
    $Result += "CT_FLAG_REQUIRE_SAME_KEY_RENEWAL"
}

if($BitFlag.Substring(23,1) -eq '1')
{
    $Result += "CT_FLAG_USE_LEGACY_PROVIDER"
}

if($BitFlag -eq '00000000000000000000000000000000')
{
    $Result += "CT_FLAG_ATTEST_NONE"
}

if($BitFlag.Substring(18,1) -eq '1')
{
    $Result += "CT_FLAG_ATTEST_REQUIRED"
}

if($BitFlag.Substring(19,1) -eq '1')
{
    $Result += "CT_FLAG_ATTEST_PREFERRED"
}

if($BitFlag.Substring(17,1) -eq '1')
{
    $Result += "CT_FLAG_ATTESTATION_WITHOUT_POLICY"
}

if($BitFlag.Substring(22,1) -eq '1')
{
    $Result += "CT_FLAG_EK_TRUST_ON_USE"
}

if($BitFlag.Substring(21,1) -eq '1')
{
    $Result += "CT_FLAG_EK_VALIDATE_CERT"
}
if($BitFlag.Substring(20,1) -eq '1')
{
    $Result += "CT_FLAG_EK_VALIDATE_KEY"
}

$Result

}
function Convert-ADCSNameFlag
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Flag
    )

# Based on 2.28 msPKI-Certificate-Name-Flag Attribute
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/1192823c-d839-4bc3-9b6b-fa8c53507ae1

$Result = @()

$BitFlag =  [convert]::ToString($Flag,2).padleft(32,'0')

if($BitFlag.Substring(31,1) -eq '1')
{
    $Result += "ENROLLEE_SUPPLIES_SUBJECT"
}

if($BitFlag.Substring(28,1) -eq '1')
{
    $Result += "OLD_CERT_SUPPLIES_SUBJECT_AND_ALT_NAME"
}

if($BitFlag.Substring(15,1) -eq '1')
{
    $Result += "ENROLLEE_SUPPLIES_SUBJECT_ALT_NAME"
}

if($BitFlag.Substring(9,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_DOMAIN_DNS"
}

if($BitFlag.Substring(7,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_DIRECTORY_GUID"
}

if($BitFlag.Substring(6,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_UPN"
}

if($BitFlag.Substring(5,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_EMAIL"
}

if($BitFlag.Substring(4,1) -eq '1')
{
    $Result += "SUBJECT_ALT_REQUIRE_DNS"
}

if($BitFlag.Substring(3,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_DNS_AS_CN"
}

if($BitFlag.Substring(2,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_EMAIL"
}

if($BitFlag.Substring(1,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_COMMON_NAME"
}

if($BitFlag.Substring(0,1) -eq '1')
{
    $Result += "SUBJECT_REQUIRE_DIRECTORY_PATH"
}

$Result

}

function Convert-ADCSEnrollmentFlag
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true, ValueFromPipeline=$true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Flag
    )

# Based on 2.26 msPKI-Enrollment-Flag Attribute
# https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-crtd/ec71fd43-61c2-407b-83c9-b52272dec8a1

$Result = @()

$BitFlag =  [convert]::ToString($Flag,2).padleft(32,'0')

if($BitFlag.Substring(31,1) -eq '1')
{
    $Result += "CT_FLAG_INCLUDE_SYMMETRIC_ALGORITHMS"
}

if($BitFlag.Substring(30,1) -eq '1')
{
    $Result += "CT_FLAG_PEND_ALL_REQUESTS"
}

if($BitFlag.Substring(29,1) -eq '1')
{
    $Result += "CT_FLAG_PUBLISH_TO_KRA_CONTAINER"
}

if($BitFlag.Substring(28,1) -eq '1')
{
    $Result += "CT_FLAG_PUBLISH_TO_DS"
}

if($BitFlag.Substring(27,1) -eq '1')
{
    $Result += "CT_FLAG_AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE"
}

if($BitFlag.Substring(26,1) -eq '1')
{
    $Result += "CT_FLAG_AUTO_ENROLLMENT"
}
if($BitFlag.Substring(25,1) -eq '1')
{
    $Result += "CT_FLAG_PREVIOUS_APPROVAL_VALIDATE_REENROLLMENT"
}

if($BitFlag.Substring(23,1) -eq '1')
{
    $Result += "CT_FLAG_USER_INTERACTION_REQUIRED"
}

if($BitFlag.Substring(21,1) -eq '1')
{
    $Result += "CT_FLAG_REMOVE_INVALID_CERTIFICATE_FROM_PERSONAL_STORE"
}

if($BitFlag.Substring(20,1) -eq '1')
{
    $Result += "CT_FLAG_ALLOW_ENROLL_ON_BEHALF_OF"
}

if($BitFlag.Substring(19,1) -eq '1')
{
    $Result += "CT_FLAG_ADD_OCSP_NOCHECK"
}

if($BitFlag.Substring(18,1) -eq '1')
{
    $Result += "CT_FLAG_ENABLE_KEY_REUSE_ON_NT_TOKEN_KEYSET_STORAGE_FULL"
}

if($BitFlag.Substring(17,1) -eq '1')
{
    $Result += "CT_FLAG_NOREVOCATIONINFOINISSUEDCERTS"
}

if($BitFlag.Substring(16,1) -eq '1')
{
    $Result += "CT_FLAG_INCLUDE_BASIC_CONSTRAINTS_FOR_EE_CERTS"
}

if($BitFlag.Substring(15,1) -eq '1')
{
    $Result += "CT_FLAG_ALLOW_PREVIOUS_APPROVAL_KEYBASEDRENEWAL_VALIDATE_REENROLLMENT"
}

if($BitFlag.Substring(14,1) -eq '1')
{
    $Result += "CT_FLAG_ISSUANCE_POLICIES_FROM_REQUEST"
}

$Result

}


function Convert-ADCSFlag
{

        [CmdletBinding()]
        Param (
        [Parameter(Mandatory = $true)]
        [ValidateSet("mspki-enrollment-flag","mspki-certificate-name-flag","mspki-private-key-flag")]
        [string]
        $Attribute,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Value)

switch($Attribute)
{
    "mspki-enrollment-flag" { Convert-ADCSEnrollmentFlag -Flag $Value }
    "mspki-certificate-name-flag"{ Convert-ADCSNameFlag -Flag $Value }
    "mspki-private-key-flag"{ Convert-ADCSPrivateKeyFlag -Flag $Value }
}


}


function Get-ADCSTemplateACL 
{

        [CmdletBinding()]
        Param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,
        
        [Parameter(Mandatory = $false)]
        [ValidateSet("AdminACEs","DefaultACEs")]
        [String]
        $Filter)
        

$DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName

$SearcherArguments = @{"SearchBase"=("CN=Certificate Templates," + $BasePath)}
$SearcherArguments.Add("LDAPFilter","(objectclass=pKICertificateTemplate)")
if ($PSBoundParameters['Name']) { $SearcherArguments['LDAPFilter'] = ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") }

$TemplatesACL = Get-DomainObjectACL @SearcherArguments -Resolveguids

foreach($acl in $TemplatesACL)
{
    $acl | Add-Member -MemberType NoteProperty -Name Identity -Value (Convert-SidToName $acl.SecurityIdentifier)
}

if($Filter -eq "AdminACEs")
{
    $TemplatesACL = $TemplatesACL | ? { -not (($_.SecurityIdentifier.value -like "*-512") -or ($_.SecurityIdentifier.value -like "*-519") -or ($_.SecurityIdentifier.value -like "*-516") -or ($_.SecurityIdentifier.value -like "*-500") -or ($_.SecurityIdentifier.value -like "*-498") -or ($_.SecurityIdentifier.value -eq "S-1-5-9")) }
}
if($Filter -eq "DefaultACEs")
{
    $TemplatesACL = $TemplatesACL | ? { -not (($_.SecurityIdentifier.value -like "*-512") -or ($_.SecurityIdentifier.value -like "*-519") -or ($_.SecurityIdentifier.value -like "*-516") -or ($_.SecurityIdentifier.value -like "*-500") -or ($_.SecurityIdentifier.value -like "*-498") -or ($_.SecurityIdentifier.value -eq "S-1-5-9") -or ($_.SecurityIdentifier.value -eq "S-1-5-11") -or ($_.SecurityIdentifier.value -like "*-513") -or ($_.SecurityIdentifier.value -like "*-515") -or ($_.SecurityIdentifier.value -like "*-553")) } 
}

$TemplatesACL

}

function Get-ADCSTemplate
{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $ResolveFlags,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $IncludeACL,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $Raw
    )

$DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName

$SearcherArguments = @{"SearchBase"=("CN=Certificate Templates," + $BasePath)}
$SearcherArguments.Add("LDAPFilter","(objectclass=pKICertificateTemplate)")
if ($PSBoundParameters['Name']) { $SearcherArguments['LDAPFilter'] = ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") }
if ($PSBoundParameters['Raw']) { $SearcherArguments['Raw'] = $Raw }

$Templates = Get-DomainObject @SearcherArguments


if($IncludeACL)
{
    $TemplatesACL = Get-ADCSTemplateACL

    foreach($t in $Templates)
    {
        $ACEs = $TemplatesACL | ? {$_.ObjectDN -eq $t.distinguishedname}
        $t | Add-Member -MemberType NoteProperty -Name "ACL" -Value $ACEs
    }
}

if($ResolveFlags)
{

    foreach($t in $Templates)
    {
        $CertificateNameFlag = Convert-ADCSFlag -Attribute mspki-certificate-name-flag -Value $t.'mspki-certificate-name-flag'
        if($CertificateNameFlag)
        {
            $t | Add-Member -MemberType NoteProperty -Name "CertificateNameFlag" -Value $CertificateNameFlag
        }

        $EnrollmentFlag = Convert-ADCSFlag -Attribute mspki-enrollment-flag -Value $t."mspki-enrollment-flag"
        if($EnrollmentFlag)
        {
            $t | Add-Member -MemberType NoteProperty -Name "EnrollmentFlag" -Value $EnrollmentFlag
        }

        $PrivateKeyFlag = Convert-ADCSFlag -Attribute mspki-private-key-flag -Value $t."mspki-private-key-flag"
        if($PrivateKeyFlag)
        {
            $t | Add-Member -MemberType NoteProperty -Name "PrivateKeyFlag" -Value $PrivateKeyFlag
        }
    }

}

$Templates

}


function Set-ADCSTemplate
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [Hashtable]
        $Properties,
        
        [Parameter(Position = 2, Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $Force

        )

$Domain = (Get-Domain).Name    
$DomainName = "DC=" + $Domain.Replace(".",",DC=")
$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName

if($Global:ADCSTEMPLATESETTINGS -and -not $Force)
{
    Write-Warning "Global state variable exists. If you go on, you may loose old data. Use -Force to override"
}
else {
        $Global:ADCSTEMPLATESETTINGS = @{}
        $template = Get-ADCSTemplate -Name $Name -Raw
        $entry = $template.GetDirectoryEntry()
        $Properties.GetEnumerator() | ForEach-Object {
            try{
                $value = $entry.Get($_.Key)
                if($value.gettype().Name -eq "Int32")
                {
                    $value = $value.ToString()
                }
            }
            catch
            {
                $value = "CLEAR"
            }
            $Global:ADCSTEMPLATESETTINGS.Add($_.Key,$value)
        }
        foreach($p in $Properties.GetEnumerator())
        {
                if($p.Value -eq "CLEAR")
                {
                    Set-DomainObject -Identity $Name -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") -Clear $p.Key
                }
                else 
                {
                    Set-DomainObject -Identity $Name -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") -Set @{$p.Key=$p.Value}
                }

        }
    }

}

function Reset-ADCSTemplate
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name)

        if(-not $Global:ADCSTEMPLATESETTINGS)
        {
            Write-Warning "No state variable found. Nothing to reset."
        }
        else
        {
            Set-ADCSTemplate -Name $Name -Properties $Global:ADCSTEMPLATESETTINGS -Force
            $Global:ADCSTEMPLATESETTINGS = ""
        }
}
function Get-SmartCardCertificate{

    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $Identity,

        [Parameter(Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [String]
        $TemplateName,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $NoSmartcard)



$STOPERROR = $false

$user = Get-DomainObject -Identity $Identity

if(-not $user)
{
    Write-Warning "User $($Identity) does not exist."
    $STOPERROR = $true
}
if(-not (Get-ADCSTemplate -Name $TemplateName))
{
    Write-Warning "Template $($TemplateName) does not exist."
    $STOPERROR = $true
}

if(-not $STOPERROR)
{

    $TargetUPN = $user.userprincipalname

    $Properties = @{}
    $Properties.Add('mspki-certificate-name-flag',1)
    $Properties.Add('pkiextendedkeyusage',@('1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.5.7.3.2'))
    $Properties.Add('msPKI-Certificate-Application-Policy',@('1.3.6.1.4.1.311.20.2.2','1.3.6.1.5.5.7.3.2'))
    $Properties.Add('flags','CLEAR')
    $Properties.Add('mspki-enrollment-flag',0)
    $Properties.Add('mspki-private-key-flag',256)
    $Properties.Add('pkidefaultkeyspec',1)

    if($PSBoundParameters['NoSmartcard'])
    {
        $Properties.Add('pKIDefaultCSPs','1,Microsoft RSA SChannel Cryptographic Provider')
        $Properties.'mspki-private-key-flag' += 16
    }
    else
    {
        $Properties.Add('pKIDefaultCSPs','1,Microsoft Base Smart Card Crypto Provider')
    }

    Write-Verbose "Changing template $TemplateName into a smartcard template"
    Set-ADCSTemplate -Name $TemplateName -Properties $Properties -Force

    Write-Verbose "Requesting certificate for $($TargetUPN)"

    $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $IANs = New-Object -ComObject X509Enrollment.CAlternativeNames
    $IAN = New-Object -ComObject X509Enrollment.CAlternativeName
    $IAN.InitializeFromString(0xB,$TargetUPN)
    $IANs.Add($IAN)
    $SAN.InitializeEncode($IANs)
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromTemplateName(0x1,$TemplateName)
    $Request.Request.X509Extensions.Add($SAN)
    $Request.CertificateFriendlyName = $TemplateName
    $Request.Enroll()

    Write-Verbose "Rolling back changes to template. Nothing happend here..."
    Reset-ADCSTemplate -Name $TemplateName

}

}

function New-VirtualSmartCard
{
    $VSCName = "VSC" + (get-random -Minimum 1000 -Maximum 9999).ToString()   
    $VSCArgs = "create /name " + $VSCName + " /pin default /adminkey random /generate"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "C:\Windows\System32\tpmvscmgr.exe"
    $pinfo.RedirectStandardError = $true
    $pinfo.RedirectStandardOutput = $true
    $pinfo.UseShellExecute = $false
    $pinfo.Arguments = $VSCArgs
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo = $pinfo
    $p.Start() | Out-Null
    $p.WaitForExit()
    $stdout = $p.StandardOutput.ReadToEnd()
    $stderr = $p.StandardError.ReadToEnd()

    if($stderr)
    {
        Write-Warning "An error occurred during VSC generation."
        Write-Warning $stderr
    }
    else {
        Write-Output "Virtual smartcard $($VSCName) created"
        Write-Output "Pin: 12345678"
    }
}

function Get-VirtualSmartCard
{
    Get-wmiobject win32_PnPEntity | ? {$_.ClassGuid -eq "{50DD5230-BA8A-11D1-BF5D-0000F805F530}"} | select-object Name, Description, DeviceID
}

function Remove-VirtualSmartCard
{
    [CmdletBinding()]
    Param (
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]
        $DeviceID)

    if($PSBoundParameters['DeviceID'])
    {
        $VSC = Get-VirtualSmartCard | ? {$_.DeviceID -eq $DeviceID}
    }
    else
    {
        $VSC = Get-VirtualSmartCard
    }

    if(-not $VSC)
    {
        Write-Warning "Virtual Smartcard not found."
    }
    else {
        
        foreach($v in $VSC)
        {
            $VSCArgs = "destroy /instance " + $v.DeviceID

            $pinfo = New-Object System.Diagnostics.ProcessStartInfo
            $pinfo.FileName = "C:\Windows\System32\tpmvscmgr.exe"
            $pinfo.RedirectStandardError = $true
            $pinfo.RedirectStandardOutput = $true
            $pinfo.UseShellExecute = $false
            $pinfo.Arguments = $VSCArgs
            $p = New-Object System.Diagnostics.Process
            $p.StartInfo = $pinfo
            $p.Start() | Out-Null
            $p.WaitForExit()
            $stdout = $p.StandardOutput.ReadToEnd()
            $stderr = $p.StandardError.ReadToEnd()

            if($stderr)
            {
                Write-Warning "An error occurred."
                Write-Verbose $stderr
            }
            else {
                Write-Output "Virtual smartcard $($v.DeviceID) deleted"
            }
        }
    }
}