This script used to load MED17 / DSG files into IDA PRO

Requirements:
Ida Pro 7.4+
Idapython

Howto:
-load bin with start address, loading address = 0x80000000, choose tricore cpu
-make autoanalyse of pflash segment to get raw code
-file -> script file

Whats inside:
-searching for global registers values (simply assignment)
-parse em in code, converts to offset (based on prjs indirect() script)
-searching for a9 global register offset
-parse direct addressing mode (sometimes not)
-handle double pointer offset // this part might be buggy (offset applies until target register assignment with some other value or 'rets')
