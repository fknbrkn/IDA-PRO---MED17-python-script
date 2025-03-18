This script for IDA PRO to parse MED17 / DSG files

<b>Requirements:</b>
Ida Pro 7.4+
Idapython

<b>Howto:</b>  
  -load bin with start address, loading address = 0x80000000, choose tricore cpu  
  -(optional if TC1793 used, choose TC1797 in list of cpus (?)) load additional binary file with these settings: ![TC1793_loading segments ida](https://github.com/user-attachments/assets/23f9d4b5-9f90-4449-85da-2943e3e4e354)
  -(optional) check for the segments, add 0xC, 0xB, 0xA segments if needed
  -make autoanalyse of pflash segment to get raw code  
  -file -> script file  
  -choose a9 register from list of results. keep in mind that its usually flash (0x80000000 based) pointer

<b>Whats inside:</b>
-searching for global registers values (simply assignment)  
-parse em in code, converts to offset (based on prjs indirect() script)  
-searching for a9 global register offset  
-parse direct addressing mode (sometimes not)  
-handle double pointer offset // this part might be buggy (offset applies until target register assignment with some other value or 'rets')  
-loading a2l definition with maps and variables + bits  
