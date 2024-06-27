import "pe"

rule TrueSight_Vuln_Driver {
    meta:
        description = "Vulnerable Truesight driver, may be used to disable AV products."
        author = "sudoREM"
        date = "2024-06-27"
        reference = "https://github.com/MaorSabag/TrueSightKiller"
    strings:
        $a = {41 00 64 00 6c 00 69 00 63 00 65 00 20 00 53 00 6f 00 66 00 74 00 77 00 61 00 72 00 65} // Adlice Software
        $b = {52 00 6f 00 67 00 75 00 65 00 4b 00 69 00 6c 00 6c 00 65 00 72} // RogueKiller
    condition:
        any of them or pe.pdb_path == "E:\\Adlice\\Truesight\\x64\\Release\\truesight.pdb"
}
