$EmailListArray = Get-Content .\CleanUsers -ErrorAction stop
$table = @()

ForEach($email in $EmailListArray)
{
$url = "https://whatpassword.australiaeast.cloudapp.azure.com:21337/whatpassword?username=$email"
$PasswordRequest = Invoke-RestMethod -Uri $url


if ($PasswordRequest.error -ne $null)
    {
    }
        else
        {
            $Username = $PasswordRequest.password.Split(':')[0].substring(2)
            $Password = $PasswordRequest.password.Split(':')[1].substring(0,$PasswordRequest.password.Split(':')[1].Length-2)
           
            
            $Output = New-Object System.Object
            $Output | Add-Member -type NoteProperty -name Username -value $Username
            $Output | Add-Member -type NoteProperty -Name Password -Value $Password
            $table += $Output
        }
}

$table | Format-Table