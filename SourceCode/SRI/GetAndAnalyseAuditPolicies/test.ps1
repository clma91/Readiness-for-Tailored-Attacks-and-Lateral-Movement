$Autos = @{
    BMW = "M2"
    Audi = "RS3"
}

$Autos.Add("Mercedes", "SLS AMG")

$Autos.GetEnumerator() | sort -Property name 
Write-Host $Autos.GetType()

foreach($Auto in $Autos.GetEnumerator()) {
    Write-Host $Auto.key
    Write-Host $Auto.value
}