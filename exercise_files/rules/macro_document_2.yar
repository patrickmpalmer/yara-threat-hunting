rule office_macro
{
    meta:
        description = "M$ Office document containing a macro"
        version = "2.0"
    strings:
        // Header DOC file
        $h1 = {d0 cf 11 e0}

        //header DOCX file
        $h2 = "PK"

        //macros in DOC files
        $m1 = "Attribut" fullword

        //macros in DOX files
        $m2 = "vbaProject.bin" nocase

        //execute when open
        $s1 = "auto_open" nocase
        $s2 = "workbook_open" nocase
        $s3 = "autoopen" nocase

    condition:
        (($h1 at 0 and $m1) or ($h2 at 0 and $m2)) and any of ($s*)
}