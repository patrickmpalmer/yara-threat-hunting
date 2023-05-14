rule office_macro
{
    meta:
        description = "M$ Office document containing a macro"
		version = "1.0"
		
    strings:
        // Header DOC file
        $h1 = {d0 cf 11 e0}

        //header DOCX file
        $h2 = "PK"

        //macros in DOC files
        $m1 = "Attribut" fullword

        //macros in DOX files
        $m2 = "vbaProject.bin" nocase

    condition:
        ($h1 at 0 and $m1) or ($h2 at 0 and $m2)
}

rule auto_open_macro
{
    meta:
        description = "Detect macro enabled documents that will execute when opening document"
    strings:
        $s1 = "auto_open" nocase
        $s2 = "workbook_open" nocase
        $s3 = "autoopen" nocase
    condition:
        ($s1 or $s2 or $s3) and office_macro
}