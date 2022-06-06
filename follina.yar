rule hunt_0day_msdt
{
    strings:
        $s1 = "!\" TargetMode=\"External\"/>" nocase wide ascii
    condition:
        all of ($s*)
}
