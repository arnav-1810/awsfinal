<# 
	This PowerShell script was automatically converted to PowerShell Workflow so it can be run as a runbook.
	Specific changes that have been made are marked with a comment starting with “Converter:”
#>
workflow awsfinal1 {
	
	# Converter: Wrapping initial script in an InlineScript activity, and passing any parameters for use within the InlineScript
	# Converter: If you want this InlineScript to execute on another host rather than the Automation worker, simply add some combination of -PSComputerName, -PSCredential, -PSConnectionURI, or other workflow common parameters (http://technet.microsoft.com/en-us/library/jj129719.aspx) as parameters of the InlineScript
	inlineScript {
		# Get the global variable 
    $accesskey = Get-AutomationVariable -Name '$access_key'
    $secretkey = Get-AutomationVariable -Name 'secret_key'
    $OMSWorkspacename = Get-AutomationVariable -Name 'OMSwkspname'
    $resourcegroupname = Get-AutomationVariable -Name 'OMSrgname'
    $customerId = Get-AutomationVariable -Name 'customerid'
    $sharedKey = Get-AutomationVariable -Name 'sharedkey'
    $profile_name = Get-AutomationVariable -Name 'profilename'
    $region = Get-AutomationVariable -Name 'region'
        Import-Module AWSPowerShell
 		Set-AWSCredentials -AccessKey $accesskey -SecretKey $secretkey -StoreAs $profile_name
 		Initialize-AWSDefaults -ProfileName $profile_name -Region $region		
		$LogType = "awscompiled"
		# Specify a field with the created time for the records
		$TimeStampField = "DateValue"
		$json10 = Get-CWMetricStatistics -MetricName CPUUtilization -Dimension @{Name = "InstanceId"; Value = "i-08b290d4ab98f79c3"} -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date) -Namespace "AWS/EC2" -Period 300 -Statistic Average | Select-Object -ExpandProperty Datapoints | ConvertTo-Json
        $json = $json10 | ConvertFrom-Json | ForEach-Object { 
    $_ | Add-Member -MemberType NoteProperty -Name 'ObjectName' -Value 'CPUUtilization' -PassThru
} | ConvertTo-Json
		# Create the function to create the authorization signature
		Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
		{
    		$xHeaders = "x-ms-date:" + $date
    		$stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
		
    		$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    		$keyBytes = [Convert]::FromBase64String($sharedKey)
		
    		$sha256 = New-Object System.Security.Cryptography.HMACSHA256
    		$sha256.Key = $keyBytes
    		$calculatedHash = $sha256.ComputeHash($bytesToHash)
    		$encodedHash = [Convert]::ToBase64String($calculatedHash)
    		$authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    		return $authorization
		}
		
		
		# Create the function to create and post the request
		Function Post-OMSData($customerId, $sharedKey, $body, $logType)
		{
    		$method = "POST"
    		$contentType = "application/json"
    		$resource = "/api/logs"
    		$rfc1123date = [DateTime]::UtcNow.ToString("r")
    		$contentLength = $body.Length
    		$signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -fileName $fileName `
        -method $method `
        -contentType $contentType `
        -resource $resource
    		$uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
		
    		$headers = @{
        		"Authorization" = $signature;
        		"Log-Type" = $logType;
        		"x-ms-date" = $rfc1123date;
        		"time-generated-field" = $TimeStampField;
    		}
		
    		$response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    		return $response.StatusCode
		
		}
		
		# Submit the data to the API endpoint
		Post-OMSData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json)) -logType $logType
		$json20 = Get-CWMetricStatistics -MetricName NetworkOut -Dimension @{Name = "InstanceId"; Value = "i-08b290d4ab98f79c3"} -StartTime (Get-Date).AddHours(-1) -EndTime (Get-Date) -Namespace "AWS/EC2" -Period 300 -Statistic Average | Select-Object -ExpandProperty Datapoints | ConvertTo-Json
        $json1 = $json20 | ConvertFrom-Json | ForEach-Object { 
    $_ | Add-Member -MemberType NoteProperty -Name 'ObjectName' -Value 'NetworkOut' -PassThru
} | ConvertTo-Json
		# Create the function to create the authorization signature
		Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
		{
    		$xHeaders = "x-ms-date:" + $date
    		$stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource
		
    		$bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    		$keyBytes = [Convert]::FromBase64String($sharedKey)
		
    		$sha256 = New-Object System.Security.Cryptography.HMACSHA256
    		$sha256.Key = $keyBytes
    		$calculatedHash = $sha256.ComputeHash($bytesToHash)
    		$encodedHash = [Convert]::ToBase64String($calculatedHash)
    		$authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    		return $authorization
		}
		
		
		# Create the function to create and post the request
		Function Post-OMSData($customerId, $sharedKey, $body, $logType)
		{
    		$method = "POST"
    		$contentType = "application/json"
    		$resource = "/api/logs"
    		$rfc1123date = [DateTime]::UtcNow.ToString("r")
    		$contentLength = $body.Length
    		$signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -fileName $fileName `
        -method $method `
        -contentType $contentType `
        -resource $resource
    		$uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"
		
    		$headers = @{
        		"Authorization" = $signature;
        		"Log-Type" = $logType;
        		"x-ms-date" = $rfc1123date;
        		"time-generated-field" = $TimeStampField;
    		}
		
    		$response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    		return $response.StatusCode
		
		}
		
		# Submit the data to the API endpoint
		Post-OMSData -customerId $customerId -sharedKey $sharedKey -body ([System.Text.Encoding]::UTF8.GetBytes($json1)) -logType $logType
	}
}