#ida pro 7.4+ script to parse MED17 file
#fknbrkn 2024


import ida_kernwin
import math
import ida_funcs
import ida_search
import ida_idaapi
import ida_bytes
import ida_ua
import ida_nalt
import ida_name
import ida_xref
import ida_idp
import re
import idautils

regs = {'a0': 0,'a1': 0,'a8': 0,'a9': 0}

class paramTypes(enumerate):
    map = 'map'
    measurement = 'measurement'
    
class A2lMap:
    def __init__(self, offset: int, id: str, size = [0,0], comment = '', info = None, bit: int = -1, paramType = None):
        self.offset = offset
        self.id = id
        self.size = size
        self.comment = comment
        self.info = info
        self.bit = bit
        self.paramType = paramType

    def __str__(self):
        return f"Offset: {hex(self.offset)}, Size: {self.size}, ID: {self.id}, Comment: {self.comment}, Info: {self.info}, type: {self.paramType}, bit: {self.bit}"

def bitmaskToBit(bitmask: int):
    if bitmask == 0x1: return 0
    bitmask = int(bitmask,16)
    if bitmask == 1: return 0
    b = 0
    while bitmask:
        bitmask >>= 1
        b += 1
    if b == 0: return -1
    return b - 1
    
def getValueFromDisasmLine(disasm_line):
 ofs = 0
 ofs2 = 0
 match = re.search(r'\(\w*[DA8]0\w{6}', disasm_line)

 if match:
  match = re.search(r'[DA8]0\w{6}', disasm_line) #main offset
  matchN = re.search(r'\+\d{1,4}',disasm_line) #additive part numeric
  matchH = re.search(r'\+0x\w{1,4}', disasm_line) #additive part hex
  
  #additive
  #print(f'{match}  {matchN} {matchH}')
  if matchN:
   ofs2 = (matchN.group(0))[1:]
   ofs2 = int(ofs2)
  if matchH:
   ofs2 = (matchH.group(0))
   if '+' in ofs2: ofs2 = int(ofs2[1:],16) #remove + symbol


  #main offset
  ofs = match.group(0)
  ofs = int(ofs,16)
  ofs_ea = ofs+int(ofs2)


  if ofs_ea != ida_idaapi.BADADDR:
   idc.create_data(ofs_ea, idc.FF_DWORD, 1, idc.BADADDR)
   target_ofs = ida_bytes.get_dword(ofs_ea)
   match = re.search(r'0x[DA8]0\w{6}', str(hex(target_ofs)))
   if match: 
    #print(f' res: {hex(ofs)} {ofs2} {match}')
    return int(match.group(0),16)
    
    

def getSegmentBounds(segment_name):

    start_address = idc.get_segm_by_sel(ida_segment.get_segm_by_name(segment_name).start_ea)
    end_address = idc.get_segm_end(start_address)
    return start_address, end_address

def processrom(min = None, max = None):
    if not min and not max:
     min, max = getSegmentBounds('PFLASH')
    print('Disassembling..')
    if min > 0: min -= 1
    curaddr = ida_search.find_unknown(min, idc.SEARCH_DOWN)
    while curaddr < max:
        if ida_funcs.add_func(curaddr) != True:
            idc.create_insn(curaddr)
            curaddr = ida_search.find_unknown(curaddr, idc.SEARCH_DOWN)
    return

def fillGlobalRegs():

 global regs
 
 print(f'Searching for global registers...')

 for line in idautils.Heads():
  disasm_line = idc.GetDisasm(line)
  if ('#@HIS' in disasm_line or '#@LOS' in disasm_line):
   #print(disasm_line)
   match = re.search(r'_([DA8]0\w{6})', disasm_line)
   if match:
    ofs = match.group(1)
    idc.create_data(int(ofs,16), idc.FF_WORD, 1, idc.BADADDR)
    
              	
 
 for line in idautils.Heads():
  disasm_line = idc.GetDisasm(line)
  #if line < 0x801063BA or line > 0x80107000: continue
  if idc.get_wide_byte(line) != 0x91: continue #movh.a


  for reg in regs:
   #if regs[reg] > 0: continue #avoiding duplicates
   if reg + ',' in disasm_line and reg + ',' in idc.GetDisasm(line+2):
    if '@HIS' in disasm_line: #defined
     segChar = (str('0x{:02x}'.format(idc.get_wide_byte(line+3))[-1]))
     regex  = segChar + '\w{7}\)'
     match = re.search(regex, disasm_line, re.IGNORECASE)
     if match:
      regs[reg] = (int('0x' + match.group(0)[:-1],16))
      print(f'[{hex(line)}] Register {reg} found with value {hex(regs[reg])}')
      #continue
      
    if '#0x' in disasm_line  and '0x' in idc.GetDisasm(line+4): #not defined
     matchHIS = re.search(r'0x\w{4}', disasm_line)
     matchLOS = re.search(r'-*0x\w{4}', idc.GetDisasm(line+4))
     if matchHIS and matchLOS:
      
      res = matchHIS.group(0)
      res = int(res,16) << 16 #HIS
     
      res += int(matchLOS.group(0),16)
      regs[reg] = (res)
      print(f'[{hex(line)}] Register {reg} found with value {hex(regs[reg])}')
      
 #print(f'Results: {regs}')
 print('Done! ***In case of duplicated results, last one were stored. Use > indirect("a0", 0x80123456) < to override if necessary')


def reg_ofs(disasm_line, startPattern) -> int:
  ofs = 0
  pH = startPattern + r'(0x\w{1,4})'
  pN = startPattern + r'(\d{1,4})'
  matchN = re.search(pN, disasm_line) #additive part numeric
  matchH = re.search(pH, disasm_line) #additive part hex
  #print(pN, pH)

  
  if matchN: ofs = int(matchN.group(1))
  if matchH: ofs = int(matchH.group(1),16)
  if startPattern + '-' in disasm_line: ofs = -ofs #sick!
  return ofs     
 ##############################################
 
def directLinks():
    replaced = 0
    print('Parsing direct addressing offsets')
    for line in idautils.Heads():
        #if line < 0x800df914 or line > 0x800df920: continue
        disasm_line = idc.GetDisasm(line)
        disasm_line4 = idc.GetDisasm(line+4)
        if 'movh.a' in disasm_line and (', #0x80' in disasm_line or ', #0xA0' in disasm_line or ', #0xD0' in disasm_line) and not '@HIS' in disasm_line:
            
            reg = print_operand(line,0)
            if not reg: continue
            if not '[' + str(reg) +']' in disasm_line4: continue
            #HIS
            ofsH = reg_ofs(disasm_line, '#')
            if not ofsH: continue
            ofsH = (ofsH) << 16
            ofsL = reg_ofs(disasm_line4, ']')
            ofs = ofsH + ofsL
            if not ofs: continue
            ida_offset.op_offset(line+4, 0, idc.REF_OFF32, -1, ofs, 0x0)
            replaced += 1
    print(f'Done, {replaced} entries replaced')
    
    
         
def indirect(reg, address):
    replaced = 0
    print(f"Parsing register {reg} with offset {hex(address)}")
    for line in idautils.Heads():
        #if line < 0x8013c210 or line > 0x8013c238: continue
        fbyte = idc.get_wide_byte(line)
        if (fbyte== 0xD9 or fbyte == 0x19 or fbyte == 0x59 or fbyte == 0x99):
            dis = idc.GetDisasm(line)
            if '['+reg+']0x' in dis or  '['+reg+']-0x' in dis or '['+reg+'](' in dis:
                ida_offset.op_offset(line, 1, idc.REF_OFF32, -1, address, 0x0)
                ida_offset.op_offset(line, 0, idc.REF_OFF32, -1, address, 0x0)
                replaced += 1
    print("Done, %d entries replaced." % replaced)
    return



def find_a9():
 #indirect script should be run before!
 print('Attempting to find a9 register..')
 a9 = None
 results = []
 for line in idautils.Heads():
  #if line < 0x8011a000 or line > 0x8011a0ff: continue
  disasm_line = idc.GetDisasm(line) 
  if not 'ld32' in disasm_line or not '[a1]' in disasm_line: continue
  # 1 method
  # mov16 d15, #0
  # 

  if ida_ua.ua_mnem(line-2) == 'mov16' and ida_ua.ua_mnem(line+4) == 'st32.w' and ida_ua.ua_mnem(line+8) == 'st16.w' and ida_ua.ua_mnem(line+10) == 'st16.w':
      print(f'[{hex(line)}] Method #1: found probably a9 link in: {disasm_line}') 
      a9 = (getValueFromDisasmLine(disasm_line))
      if a9:
          print(f'[{hex(line)}] +Found a9 offset: {hex(a9)}')
          results.append(a9)
      else:
          print(f'No luck!')
   
  # 2 method
  # sha32           d0, d2, #2

  if 'sha32' in idc.GetDisasm(line-4) and '#2' in idc.GetDisasm(line-4) and 'addsc' in idc.GetDisasm(line+4) and '#0' in idc.GetDisasm(line+4):
      print(f'[{hex(line)}] Method #2: found probably a9 link in: {disasm_line}')
      a9 = (getValueFromDisasmLine(disasm_line))
      if a9:
          print(f'[{hex(line)}] +Found a9 offset: {hex(a9)}')
          results.append(a9)
          #continue 
      else:
          print(f'No luck!')
 
 a9 = None
 if len(results) == 0:
    print('No results found for a9 register, BYE!')
    return None
 #checking results for different values
 resultsCount = {}
 for i in set(results):
    resultsCount[i] = results.count(i)

 if len(resultsCount) == 1: #no different offsets, all ok
  a9 = results[0]
 else:
  x = 'Multiple offsets has been found! \n Enter preferred a9 value with format 0x80123456 \n Results: \n'
  x += ''.join('['+hex(i)+']\n' for i in results)
  print(results)
  q = ida_kernwin.ask_text(10,str(hex(results[0])),x)
  if not q: return None
  if '0x80' in q and len(q) == 10:
   try:
    a9 = int(q,16)
   except:
    print(f'User input {x} not defined as a hex number, use 0x80123456 format')
    return None
  else: print(f'Wrong user input {x} !')
    
 print(f'Register a9 defined as {hex(a9)}')
 return a9 
    
def secondLayerLinks(reg, target_reg):
    
    print(f'Proceed with {reg} indirect offsets, target: [{target_reg}]')
    ofs = None
    count = 0
    for line in idautils.Heads():
      disasm_line = idc.GetDisasm(line)
      #if line < 0x800EFF6E or line > 0x800EFF9C: continue #################################
      if target_reg and ofs: 
        #if target_reg had some offset
        if '['+target_reg+']' in disasm_line:
         #finally magic is here
         ida_bytes.del_items(ofs)
         if '16' in str(ida_ua.ua_mnem):
          idc.create_data(ofs, idc.FF_WORD, 1, idc.BADADDR)
         else:
          idc.create_data(ofs, idc.FF_DWORD, 1, idc.BADADDR)
         ida_offset.op_offset(line, 1, idc.REF_OFF32, -1, (ofs), 0x0)
         count +=1
         
        #TODO!!!!
        #if target_reg+',' in disasm_line or 'ret' in disasm_line:
        # ofs = None

      if target_reg + ', ['+reg+'](' in disasm_line and ('ld32' in disasm_line or 'lea' in disasm_line): 
        #print(f'{disasm_line}')
        ofs = getValueFromDisasmLine(disasm_line)
        
        if not ofs: continue
        idc.create_data(ofs, idc.FF_DWORD, 1, idc.BADADDR)

        if not '0x8' in str(hex(ofs)) and not '0xa' in str(hex(ofs)) and not '0xd' in str(hex(ofs)): continue
        if len(str(hex(ofs))) != 10: continue
        #if not target_reg: target_reg = print_operand(line,0)
    
    print(f'Done... {str(count)} entries replaced')
 
def parse_characteristic_block(block) -> A2lMap:
    #print(block)
    lines = block.split('\n')
    map = A2lMap(None,None, paramType=paramTypes.map)
    try:
        for line in lines:
            if not line: continue
            if line and not map.id: map.id = line.strip()
            
            if '"' in line and not map.comment: map.comment = line.lstrip()
            if map.offset and not map.info:
                map.info = 8
                if '32' in line or 'DWORD' in line: map.info = 32
                if '16' in line or 'WORD' in line: map.info = 16
            if '0x' in line and not map.offset: map.offset = int(line.strip(),16) 
    except:
        print(f'Error in parsing a2l block: {block}')
    #print(map)    
    return map

def parse_measurement_block(block) -> A2lMap:
    #print(block)
    lines = block.split('\n')
    map = A2lMap(None,None, paramType=paramTypes.measurement)
    try:
    
        for line in lines:
            if not line: continue
            if line and not map.id: map.id = line.strip()
            if '"' in line and not map.comment: map.comment = line.lstrip()
            if 'UBYTE' in line or 'SBYTE' in line: map.info = 8
            if 'UWORD' in line or 'SWORD' in line: map.info = 16
            if 'ECU_ADDRESS' in line and not map.offset: map.offset = int(line.replace('ECU_ADDRESS','').strip(),16) 
            if 'DISPLAY_IDENTIFIER' in line: map.id = line.replace('DISPLAY_IDENTIFIER','').strip()
            if 'BIT_MASK' in line: 
                bit = bitmaskToBit(line.replace('BIT_MASK','').strip())
                if bit >= 0:
                    map.bit = bit
                else:
                    print(f'Failed to parse bitmask >{line.replace("BIT_MASK","").strip()}<' ) 
    except:
        print(f'Error in parsing a2l block: {block}')   
    return map
 
def assign_enums():
    #direct
    print('Assign enums... direct')
    for line in idautils.Heads():
      disasm_line = idc.GetDisasm(line)
      #if line < 0x80096418 or line > 0x80096500: continue #################################
      if idc.get_wide_byte(line) == 0x6F or idc.get_wide_byte(line) == 0xD5:
          if ':' in disasm_line:
              if idc.get_wide_byte(line) == 0xD5: opnum = 0 
              else: opnum = 1
              enm_id = get_enum('enm_'+ str(hex(get_operand_value(line,opnum))))
              if enm_id == 18446744073709551615 or enm_id == 0xffffffffffffffff: continue
              op_enum(line,1,enm_id,0)
    #indirect
    print('Assign enums... indirect')
    op = None
    enm_id = None
    for line in idautils.Heads():
        disasm_line = idc.GetDisasm(line)
        if not disasm_line: continue
        if op and enm_id:
           if op+',' in disasm_line: 
               op = None 
               enm_id = None
               
        if op and enm_id:
            if op+':' in disasm_line:
               op_enum(line,1,(enm_id),0) 
        
        if idc.get_wide_byte(line) == 0x05: #ld
          enm_id = get_enum('enm_'+ str(hex(get_operand_value(line,1))))
          if enm_id == 0xffffffffffffffff or enm_id == 18446744073709551615:
             enm_id = None
          else: op = str(print_operand(line,0))
        
    
          
          
     
 
def load_a2l():
    
    if not ida_kernwin.ask_yn(1,"Load a2l file?","Do you want to load a2l file?"): return
    
    
    filename = ida_kernwin.ask_file(False, "*.a2l", "Select a2l file")

    if filename:

        
        with open(filename, 'r') as file:
            print(f'Trying to parse a2l file {filename}')
            cnt = 0
            block = ''
            e = add_enum(1, 'Condition',0)
            ida_enum.add_enum_member(e,'True',1)
            ida_enum.add_enum_member(e,'False',0)
            #measurements
            for line in file:
                ignoreLine = False
                #if cnt == 10: break
                if '/begin MEASUREMENT' in line: 
                    cnt += 1
                    block = ' '
                
                elif '/end MEASUREMENT' in line:
                    if block:
                        var = parse_measurement_block(block)

                        #if not var.offset or not var.id: continue
                        if var.info:
                            if var.info == 8: idc.create_data(var.offset, idc.FF_BYTE, 1, idc.BADADDR)
                            if var.info == 16: idc.create_data(var.offset, idc.FF_WORD, 1, idc.BADADDR)
                            if var.info == 32: idc.create_data(var.offset, idc.FF_DWORD, 1, idc.BADADDR)
                            
                        if var.bit >= 0:
                            #print(var)
                            idc.set_name(var.offset, '') #unset name
                            enm = get_enum('enm_' + str(hex(var.offset)))
                            if enm == 18446744073709551615 or not enm: enm = add_enum(-1, 'enm_' + str(hex(var.offset)),1)
                            ida_enum.add_enum_member(enm,var.id,var.bit)
                            enmm = get_enum_member_by_name(var.id)
                            ida_enum.set_enum_member_cmt(enmm,var.comment,1)
                            
                            
                        else: 
                            idc.set_name(var.offset, var.id)
                            idc.set_cmt(var.offset, var.comment,1)
             
                                                   
                        
                    block = None
                
                elif block: block += line
                
            print(f'{cnt} measurements find')
            cnt = 0
            #return
            #characteristics
            for line in file:
                ignoreLine = False                
                #if cnt == 10: break
                if '/begin AXIS' in line and block: ignoreLine = True
                if '/end AXIS' in line and block: ignoreLine = False               
                
                if '/begin CHARACTERISTIC' in line:
                    cnt += 1
                    block = ' '

                elif '/end CHARACTERISTIC' in line: 
                    if block: 
                        map = parse_characteristic_block(block)
                        #print(map)
                        try:
                            if map:
                                map.id = map.id.replace('"','_')
                                if map.offset and map.info:
                                    if map.info == 8: idc.create_data(map.offset, idc.FF_BYTE, 1, idc.BADADDR)
                                    if map.info == 16: idc.create_data(map.offset, idc.FF_WORD, 1, idc.BADADDR)
                                    if map.info == 32: idc.create_data(map.offset, idc.FF_DWORD, 1, idc.BADADDR)
                                else:
                                    idc.create_data(map.offset, idc.FF_BYTE, 1, idc.BADADDR)                      
                                idc.set_name(map.offset, map.id + '_map')
                                if map.comment: idc.set_cmt(map.offset, map.comment, 1)
                        except: print(f'Creating data failed: {map}')
                    block = None
        
                elif block and not ignoreLine: block += line
                
            print(f'{cnt} characteristics found')
            
            #measurements
            
            assign_enums()
    
    
       
def med17_main():
   
    auto_wait()
    fillGlobalRegs()
    auto_wait()
    
    directLinks()
    auto_wait()
    
    #convert hex to offset in code with global registers
    for reg, value in regs.items():
        auto_wait()
        if value == 0 and reg == 'a9':
            print(f'[!!!] Failed to find a9 offset, trying a9 special methods:')
            value = find_a9()
            if value: regs[reg] = value
            
        if value == 0 or value == None:
            print(f'[!!!] Failed to find {reg} offset, use > indirect("{reg}", offset) < for manual definition')
        else:
            indirect(reg,value)
    pass
    print('Initial parsing finished')
    
    for reg, value in regs.items():
        if value == 0 or value == None: continue
        if '0xd' in str(hex(value)) or '0xc' in str(hex(value)): 
            print('This is RAM offset, skipping..')
            continue
        for i in range(2,16):
            if i in {8,9}: continue #exclude a8, a9 targets
            secondLayerLinks(reg, 'a'+str(i))
            auto_wait()
        
    
    load_a2l()
    print('Finished!')
        


med17_main()
