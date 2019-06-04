#Open As Admin
If (-NOT ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))

{ 
    
#This script was created  by Tom Bindloss - 2019
#You're free to use this script however you please.
# You can find more of my scripts here - https://github.com/TomBindloss    

$arguments = "& '" + $myinvocation.mycommand.definition + "'"
Start-Process powershell -Verb runAs -ArgumentList $arguments
Break
}
#Exchange Login Creds Below
$PSUser = 'Username - Normally an email'
$PSPass = 'Password'
$PsPassword = ConvertTo-SecureString -AsPlainText $PSPass -Force
$SecureString = $PsPassword
$PSCreds = New-Object System.Management.Automation.PSCredential($PSUser,$PsPassword)

#Email Logins - Used to email credentials - can be deleted
$email_username = "Exchange username";
$email_password = "Sending from password";
$email_smtp_host = "SMTP Host address";
$email_smtp_port = 25;
$email_smtp_SSL = 0;
$email_from_address = "Sending from address";
$email_to_addressArray = @("Address to 1" ,"Address to 2"); 
#Startup
echo "Script originally created by Tom Bindloss - 2019"
Start-Sleep -Milliseconds 300

Import-Module ActiveDirectory

#Input User Data
    $fname = Read-Host -Prompt "Input First Name"
    $Lname = Read-Host -Prompt "Input Surname"
    $Jtitle = Read-host -Prompt "Input Job Title"
    $Initials = Read-Host -Prompt "Tikit Login"
    $Department = Read-host -prompt "Input Department - Put 'None' if not known"
    $PasswordInput =Read-host -Prompt "Enter a password"
    $Securepassword = ConvertTo-SecureString $PasswordInput -AsPlainText -Force
    $SAMName = "$fname$lname"

#Office Information
    $Number = 'Phone Number'
    $Street = "First Address line - e.g. 1 main street"
    $City = 'Town'
    $PCode = 'Post Code'
    $OGroup = 'OU Group in AD'

Echo "Please ensure following is correct.
Name - $Fname $lname
Title - $Jtitle
Department - $Department
"
read-host -Prompt 'Press Enter to continue'

#IF Function for department - Insert Departments Below

  if ($department -eq 'Place Department name here'){
     $OUPath = "Place OU Path here"
     $Domain = 'Place email domain here'
     $SecGroup = "Place security group here"
  }
  if ($department -eq 'Example 1'){
    $Team = read-host -Prompt "This can be used to specify sub departments - e.g. Finance - Customer or Office"
        if ($Team -eq "Example 1 sub 1"){
        $OUPath = "OU Group 1 - Customer Finance"
        $SecGroup = "Customer Finance"
        $Domain = 'example.co.uk'
        }
        if ($Team -eq "Example 1 sub 2"){
        $OUPath = "OU Group 2 - Office Finance"
        $SecGroup = "Office Finance"
        $Domain = 'example2.co.uk'
        }
  }
  if ($Department -eq 'None'){
    $OUPath = "Default Users OU"
    $SecGroup = ""
    $Domain = 'Default domain'
  }
echo "Creating account for $fname $lname"
New-ADuser -Initials $Initials -DisplayName "$fname $lname" -name "$Fname $Lname" -Title $Jtitle -Office $Office -Accountpassword $Securepassword -Path $Oupath -EmailAddress "$fname.$lname@$domain" -GivenName $fname -Surname $lname -UserPrincipalName "$Fname.$Lname@$Domain" -OfficePhone $number -StreetAddress $Street -city $City -PostalCode $Pcode -SamAccountName $SAMName
Enable-ADAccount -Identity $SAMName

Set-ADUser "$SAMName" -Add @{ProxyAddresses="SMTP:$fname.$lname@$Domain"}

#Add user to AD groups
Echo "Adding $Fname $lname to Groups"
Start-Sleep -Milliseconds 400
Add-ADGroupMember -Identity 'Add domain groups' -Members $SAMName
Add-ADGroupMember -Identity $OGroup -Members $SAMName
Add-ADGroupMember -Identity $SecGroup -Members $SAMName

 $message = new-object Net.Mail.MailMessage;
    $message.From = $email_from_address;
    foreach ($to in $email_to_addressArray) {
      $message.To.Add($to);
    }
    $message.Subject =   ("New User Created");
    $Message.Body +=   "New User Created"
    $message.Body +=   "`r`n";
    $message.Body +=   "--------------------------------------------------------------";
    $message.Body +=   "`r`n";
    $message.Body +=   ("Name - $fname $lname");
    $message.Body +=   "`r`n";
    $message.Body +=   ("Username -$fname$lname")
    $message.Body +=   "`r`n";
    $message.Body +=   ("Email - $fname.$lname@$domain")
    $message.Body +=   "`r`n";
    $message.Body +=   ("Password -$PasswordInput")
    $message.Body +=   "`r`n";
    $message.Body +=   ("Deparment -$Department")
    $message.Body +=   "`r`n";
    $message.Body +=   ("This script was created by Tom Bindloss - 2019")
    $message.Body +=   "`r`n";
    {
       
   }
    $message.Body +=   "--------------------------------------------------------------";
    $smtp = new-object Net.Mail.SmtpClient($email_smtp_host, $email_smtp_port);
    $smtp.EnableSSL = $email_smtp_SSL;
    $smtp.Credentials = New-Object System.Net.NetworkCredential($email_username, $email_password);
    $smtp.send($message);
    $message.Dispose();
    write-host "... E-Mail sent!" ; 




#start-countdown function
function start-countdown {
  param (
      $sleepintervalsec
   )

   foreach ($step in (1..$sleepintervalsec)) {
      write-progress -Activity "Waiting" -Status "Waiting - Press any key to stop" -SecondsRemaining ($sleepintervalsec-$step) -PercentComplete  ($step/$sleepintervalsec*100)
      start-sleep -seconds 1
   }
}


#Connect with exchange
$UPNEmail = "$fname.$lname@$domain"
echo "Connecting with exchange - this may take a few minutes"
start-countdown 120

$SerbUser = "Domain Service Admin Username"
$SerbPass = "Domain service admin password"
$SerbPassword = ConvertTo-SecureString -AsPlainText $SerbPass -Force
$SerbSecureString = $SerbPassword
$SerbSCreds = New-Object System.Management.Automation.PSCredential($SerbUser,$SerbSecureString)
$Serber = 'Active Directory Server'
Invoke-Command -ComputerName $Serber { Start-ADSyncSyncCycle -PolicyType Initial } -Credential $SerbSCreds

start-countdown 300
Connect-MsolService -Credential $PSCreds
Set-MsolUser -UserPrincipalName $UPNEmail -UsageLocation "GB"
Set-MsolUserLicense -UserPrincipalName $UPNEmail -AddLicenses "Put desired license in here - e.g. example:O365_BUSINESS_ESSENTIALS" 
echo "License Assigned"




#Ending - The Old Razzle Dazzle

Start-Sleep -Milliseconds 1000
echo "Account Created - Credentials

Login - $fname$lname 
Email - $fname.$lname@$domain
Password - $PasswordInput
"

Start-Sleep -Milliseconds 1000
Read-host -prompt "Press ENTER to close"
 