workflow aws_control
{ 
    $list1 = Get-automationvariable -name "EC2"
    $list2 = Get-automationvariable -name "CLOUDTRAIL"
    $list3 = Get-automationvariable -name "RDS"

    if($list1 -eq "True")
  
  {   $metric = Get-AutomationVariable -Name 'aws_metricname'
$final_array = inlineScript {
		
        $myString = $using:metric
$final_array = @($myString.Split(","))
Write-Output $final_array
}
$metric_perf = Get-AutomationVariable -Name 'aws_dimensionperf'
$final_array_dim = inlineScript {
        $myString = $using:metric_perf
$final_array_dim = @($myString.Split(","))
Write-Output $final_array_dim
}
Foreach ($metric in $final_array){
    Foreach ($metric3 in $final_array_dim){
   $oms_input = aws_export -metricnameinput $metric -dimension1input "InstanceId" -dimension2input $metric3 -namespaceinput "AWS/EC2"
   omsinput -oms_input $oms_input
    }
 }
}

if($list2 -eq "True")
{
     $metric_cl = Get-AutomationVariable -Name 'aws_metricscloudtrail'
$final_array_cloudtrail = inlineScript {
		
        $myString = $using:metric_cl
$final_array_cloudtrail = @($myString.Split(","))
Write-Output $final_array_cloudtrail
}
$metric_cl1 = Get-AutomationVariable -Name 'aws_dim_cloudtrail'
$final_array_dimcloud = inlineScript {
        $myString = $using:metric_cl1
$final_array_dimcloud = @($myString.Split(","))
Write-Output $final_array_dimcloud
}
Foreach ($metric_1 in $final_array_cloudtrail){
    Foreach ($metric4 in $final_array_dimcloud){
$oms_input_cloudtrail = aws_export -metricnameinput $metric_1 -dimension1input "LogGroupName" -dimension2input $metric4 -namespaceinput "AWS/Logs"
   omsinput_cloudtrail -oms_input $oms_input_cloudtrail
    } 
 }
}
if($list3 -eq "True")
{
    $metric_cl = Get-AutomationVariable -Name 'aws_metricsrds'
$final_array_rds = inlineScript {
		
        $myString = $using:metric_cl
$final_array_rds = @($myString.Split(","))
Write-Output $final_array_rds
}
$metric_cl1 = Get-AutomationVariable -Name 'aws_dim_rds'
$final_array_dimrds = inlineScript {
        $myString = $using:metric_cl1
$final_array_dimrds = @($myString.Split(","))
Write-Output $final_array_dimrds
}
Foreach ($metric_2 in $final_array_rds){
    Foreach ($metric_5 in $final_array_dimrds){
$oms_input_rds = aws_export -metricnameinput $metric_2 -dimension1input "DBInstanceIdentifier" -dimension2input "arnavdbinstance"  -namespaceinput "AWS/RDS"
   omsinput_rds -oms_input $oms_input_rds
   }  
 }
}
}
