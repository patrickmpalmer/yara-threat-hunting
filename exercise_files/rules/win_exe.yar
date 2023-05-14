rule Microsoft_Executable
{
    meta:
        description = "Microsoft Executable"
    strings:
        $a = {4d 5a}
        $b = "!This program cannot be run in DOS mode."
    condition:
        $a at 0 and $b
}
