rule backdoor_custom {
   meta:
      description = "evil - file backdoor.exe"
      version = "1.0"
   strings:
      $mz = {4d 5a}
      $ip = "192.168.55.137" fullword ascii
   condition:
      $mz at 0 and $ip
}