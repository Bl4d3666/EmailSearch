$text = @'                                        
 
.     .       .  .   . .   .   . .    +  .
  .     .  :     .    .. :. .___---------___.
       .  .   .    .  :.:. _".^ .^ ^.  '.. :"-_. .
    .  :       .  .  .:../:            . .^  :.:\.
        .   . :: +. :.:/: .   .    .        . . .:\
 .  :    .     . _ :::/:               .  ^ .  . .:\
  .. . .   . - : :.:./.                        .  .:\
  .      .     . :..|:                    .  .  ^. .:|
    .       . : : ..||        .                . . !:|
  .     . . . ::. ::\(                           . :)/
 .   .     : . : .:.|. ######              .#######::|
  :.. .  :-  : .:  ::|.#######           ..########:|
 .  .  .  ..  .  .. :\ ########          :######## :/
  .        .+ :: : -.:\ ########       . ########.:/
    .  .+   . . . . :.:\. #######       #######..:/
      :: . . . . ::.:..:.\           .   .   ..:/
   .   .   .  .. :  -::::.\.       | |     . .:/
      .  :  .  .  .-:.":.::.\             ..:/
 .      -.   . . . .: .:::.:.\.           .:/
.   .   .  :      : ....::_:..:\   ___.  :/
   .   .  .   .:. .. .  .: :.:.:\       :/
     +   .   .   : . ::. :.:. .:.|\  .:/|
     .         +   .  .  ...:: ..|  --.:|
.      . . .   .  .  . ... :..:.."(  ..)"
 .   .       .      :  .   .: ::/  .  .::\
 
'@


Function Invoke-EmailSearch{   
    <#
    
	.SYNOPSIS
    Report breached Emails via the sites https://haveibeenpwned.com API service.
    Import-Module SearchPasswords.ps1

    Author: Michael Merlino
    License: Free
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION
    The will connect to the websites via their api and check if the email address has been listed on any dumps.
    
    .PARAMETER UserList
    A file to import the emails.

    .PARAMETER OutFile
    A file to output the results to.
        
    .EXAMPLE
    
    C:\PS> Invoke-EmailSearch -EmailList emails.txt
    
    Description
    -----------
    Search against an email list.
     
    .EXAMPLE
    
    C:\PS> Invoke-EmailSearch -EmailList emails.txt -OutFile email
    
    Description
    -----------
    Search against an email list and outputs it to a file
   
    #>

    Param(

     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $EmailList = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $OutFile

    )

Write-Host `n $text -ForegroundColor Green

    ###### URL Email lookups ######
    $hibpURL = "https://haveibeenpwned.com/api/v2/breachedaccount/"
    
    ###### Database lookups ######
    $DatabaseRequest = Invoke-WebRequest 'https://raidforums.com/Announcement-Database-Index-CLICK-ME'

    ###### Chrome 72 on Windows 10 ######
    $UserAgentString = "HaveIBeenPwned Powershell Module"
      
    if ($EmailList -eq "")
    {
    Write-Host -ForegroundColor "red" "[*] Could find Email List. Try again specifying the Email List with the -EmailList option."
    break 
    }
    
    else
    {
        ###### If a Email List is specified use it ######
        Write-Host "[*] Using Email list"
        $EmailListArray = @()
        try 
        {
            $EmailListArray = Get-Content $EmailList -ErrorAction stop
        }
        catch [Exception]{
            Write-Host -ForegroundColor "red" "$_.Exception"
            break
        }
    
    }
$HTML = '<table>'
$HTML += '<tbody>'
$HTML += '<tr>'
$HTML += '<td width="750px;" style="background-color: blue; text-align: center;"><span style="color: White;">Title</span></td>'
$HTML += '<td width="150px;" style="background-color: blue; text-align: center;"><span style="color: White;">AddedDate</span></td>'
$HTML += '<td width="150px;" style="background-color: blue; text-align: center;"><span style="color: White;">BreachDate</span></td>'
$HTML += '<td width="250px;" style="background-color: blue; text-align: center;"><span style="color: White;">PwnCount</span></td>'
$HTML += '<td width="750px;" style="background-color: blue; text-align: center;"><span style="color: White;">URL</span></td>'
$HTML += '<td width="500px;" style="background-color: blue; text-align: center;"><span style="color: White;">Email</span></td>'
$HTML += '<td width="100px;" style="background-color: blue; text-align: center;"><span style="color: White;">Database Found</span></td>'
$HTML += '</tr>'
$HTML += '<tr>'



################### Make the magic happen ###################

    $timestarted = Get-Date
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    Write-Host -ForegroundColor Yellow "[*] Let the Hacking Being. Current time is $($timestarted.ToShortTimeString())"
    Write-Host "[*] Looking up Now"
    $current_email = 0
	
ForEach($Email in $EmailListArray)
{     
        
################### Have I been Pwned ###################
$hibp = 0

[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
    $hibpUri = $Null
    $hibprequest = $Null
    $hibpUri = $hibpURL+$Email
    
try
        {
			[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
             $hibprequest = Invoke-RestMethod -Uri $hibpUri -UserAgent $UserAgentString
        }
         Catch [System.Net.WebException] {
            Switch ($_.Exception.Message) {
                'The remote server returned an error: (400) Bad Request.' {
                    Write-Error -Message 'Bad Request - the account does not comply with an acceptable format.'
                }
                'The remote server returned an error: (403) Forbidden.' {
                    Write-Error -Message 'Forbidden - no user agent has been specified in the request.'
                }
                'The remote server returned an error: (404) Not Found.' {
                    $hibpResponse = New-Object PSObject -Property @{
                        'Account Exists' = 'False'
                        'Status' = 'Good'
                        'Description' = 'Email address not found.'
                    }
                }
                'The remote server returned an error: (429) Too Many Requests.' {
                    Write-Error -Message 'Too many requests - the rate limit has been exceeded.'
                }
            }
            
        }

$HTML += '</tr>'
$HTML += '<tr>'

    if($hibprequest -ne $null)
        {   
            $hibpCount = $hibprequest.Count - 1 
            Write-Host -ForegroundColor Green "[*] SUCCESS! User: $Email founded on Have I Been Pwned"
            Write-Host `t "[*] Data"
            
            while ($hibp -le $hibpCount )
            { 
                write-host -ForegroundColor white  `t`t "Title:" $hibprequest[$hibp].Title
                write-host -ForegroundColor white `t`t "AddedDate:" $hibprequest[$hibp].AddedDate
                write-host -ForegroundColor white `t`t "BreachDate:" $hibprequest[$hibp].BreachDate
                write-host -ForegroundColor white `t`t "PwnCount:" $hibprequest[$hibp].PwnCount
                write-host -ForegroundColor white `t`t "URL: No URL with HIBP"
                
                If ($hibprequest[$hibp].Title -like "* *")
                {
                $DatabaseFound = $DatabaseRequest.tostring() -split "[`r`n]" | Select-String $hibprequest[$hibp].Title.Split(' ')[0]
                }
                else
                {
                $DatabaseFound = $DatabaseRequest.tostring() -split "[`r`n]" | Select-String $hibprequest[$hibp].Title.Split('.')[0]
                }                      
                
                        if ($DatabaseFound -ne $null)
                            {
                            Write-Host -ForegroundColor White `t`t "Database: Found it" `n
                            $Found = 'Yes'
                            }
                        Else
                            {
                            Write-Host -ForegroundColor White `t`t "Database: Not found :(" `n
                            $Found = 'No'
                            }
                  
                $HTML += '<td>' + $hibprequest[$hibp].Title  +'</td>'  
                $HTML += '<td style="text-align: center;">' + $hibprequest[$hibp].AddedDate.Substring(0,$hibprequest[0].AddedDate.Length-10) + '</td>' 
                $HTML += '<td style="text-align: center;">' + $hibprequest[$hibp].BreachDate.Substring(0,$hibprequest[0].AddedDate.Length-10) + '</td>' 
                $HTML += '<td style="text-align: center;">' + $hibprequest[$hibp].PwnCount + '</td>' 
                $HTML += '<td> No URL with HIBP </td>'
                $HTML += '<td>' + $Email + '</td>' 
                $HTML += '<td>' + $Found + '</td>'
                $HTML += '</tr>'
                $HTML += '<tr>'
                $hibp++
                              
            }  

        }
    else
        {
            Write-Host -ForegroundColor Red "[*] Failed! User:$Email not founded on Have I Been Pwned"
        }
        $current_email++ 
        Write-Host "$current_email of "$EmailListArray.Count " users tested`r"  
     
#######This is due to the api HIBP
sleep 5

}

$HTML += '</tr>'
$HTML += '</tbody>'
$HTML += '</table>'

    if ($OutFile -ne "")
    {
        Add-Content -Path "$OutFile.html" $HTML
        Write-Host -ForegroundColor Green "[*] Any dumps that were founded have been output to $OutFile.html"
    }
    
    Write-Host -ForegroundColor Green "[*] Dumping complete" `n
    $timefinished = Get-Date
    $stopwatch.Stop()
    Write-Host -ForegroundColor Yellow "Current time is $($timefinished.ToShortTimeString()) it took" $stopwatch.Elapsed.Minutes "Minutes"
}

Function Invoke-HashSearch{   
    <#
    
	.SYNOPSIS
    Report breached Emails via the sites https://hacked-emails.com API service.
    Import-Module EmailLookup.ps1

    Author: Michael Merlino
    License: Free
    Required Dependencies: None
    Optional Dependencies: None
    
    .DESCRIPTION
    The will connect to the websites via their api and check if the hash with plain text passwords.
    
    .PARAMETER HashList
    A file to import the emails.

    .PARAMETER OutFile
    A file to output the results to.
        
    .EXAMPLE
    
    C:\PS> Invoke-HashSearch -Hashlist hash.txt
    
    Description
    -----------
    Search against an email list.
     
    .EXAMPLE
    
    C:\PS> Invoke-EmailSearch -EmailList emails.txt -OutFile email
    
    Description
    -----------
    Search against an email list and outputs it to a file
   
    #>

    Param(

     [Parameter(Position = 0, Mandatory = $false)]
     [string]
     $Hashlist = "",

     [Parameter(Position = 1, Mandatory = $false)]
     [string]
     $OutFile

    )
Write-Host `n $text -ForegroundColor Green

###### URL Hash lookups ######
    $APIKey = Read-Host -Prompt 'Enter you API Key' 
    $HashesURL = "https://hashes.org/api.php?key=$APIKey&query="    

    if ($Hashlist -eq "")
    {
    Write-Host -ForegroundColor "red" "[*] Could find Hash List. Try again specifying the Hash List with the -Hashlist option."
    break 
    }
   
   else
    {
        ###### If a Email List is specified use it ######
        Write-Host "[*] Using Hash list"
        $HashArray = @()
        try 
        {
            $HashArray = Get-Content $Hashlist -ErrorAction stop
        }
        catch [Exception]{
            Write-Host -ForegroundColor "red" "$_.Exception"
            break
        }
    }

    $timestarted = Get-Date
    $stopwatch = [Diagnostics.Stopwatch]::StartNew()
    Write-Host -ForegroundColor Yellow "[*] Let the searching being. Current time is $($timestarted.ToShortTimeString())"
    Write-Host "[*] Searching Now"
    $current_hash = 0
	   

ForEach($Hash in $HashArray){
    $URLHash = $HashesURL+$Hash
    $Hashesequest = Invoke-RestMethod $URLHash
    $Plantext = $Hashesequest.result.$Hash.plain

    if ($Plantext -contains $null)
        {
            write-host -ForegroundColor Red 'Password Not Found for hash' $hash ':('
        }
    else
        {
            Write-Host -ForegroundColor Green '[*] Password found for hash' $hash 'Plan text is' $Plantext
            $Report += "[*] Password found for hash " + $hash + " Plan text is "+ $Plantext | Out-String
            $current_hash ++
        }
}

    if ($OutFile -ne "")
    {
        Add-Content -Path "$OutFile.txt" $Report
        Write-Host -ForegroundColor Green "[*] Any dumps that were founded have been output to $OutFile.txt"
    }
    
    Write-Host -ForegroundColor Green "[*] Dumping complete" `n
    Write-Host -ForegroundColor Green "[*] Hashes found  $current_hash" `n
    $timefinished = Get-Date
    $stopwatch.Stop()
    Write-Host -ForegroundColor Yellow "Current time is $($timefinished.ToShortTimeString()) it took" $stopwatch.Elapsed.Seconds "Seconds"
}