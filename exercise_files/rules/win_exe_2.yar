import "pe"

rule Microsoft_Executable_2
{
    meta:
        description = "Microsoft Executable"
		version = "2.0"
    condition:
        (pe.machine == pe.MACHINE_I386 or 
        pe.machine == pe.MACHINE_AMD64) and not
         pe.characteristics & pe.DLL
        
}
