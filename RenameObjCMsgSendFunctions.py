# Rename functions that Ghidra names as "FUN_xxx" to "msgSend_<selector>"
# where <selector> is the Objective-C selector found in the function body.
# Only for ARM64 binaries.

#@author p1tsi
#@category Objective-C
#@keybinding 
#@menupath 
#@toolbar 
#@runtime Jython


"""
EXAMPLE:

Function like this:

                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             undefined FUN_100034840()
             undefined         <UNASSIGNED>   <RETURN>
                             FUN_100034840                           XREF[5]:

       100034840 e1 00 00 d0     adrp       x1,0x100052000
       100034844 21 14 46 f9     ldr        x1=>s_valueForKey:_10003ddf1,[x1, #0xc28]=>PTR   = "valueForKey:"

       100034848 91 00 00 90     adrp       x17,0x100044000
       10003484c 31 02 0c 91     add        x17,x17,#0x300
       100034850 30 02 40 f9     ldr        x16,[x17]=>->_objc_msgSend
       100034854 11 0a 1f d7     braa       x16=>_objc_msgSend,x17                           undefined _objc_msgSend()

Will be renamed:

    FUN_100034840  ->  msgSend_valueForKey_  

"""

import ghidra


# TODO: change logic so that the starting point is all the xref to objc_msgSend
#  and then go backwards to find the selector


# Create a global variable that contains the address of objc_msgSend
objc_msgSend_addr = None
for func in currentProgram.getFunctionManager().getFunctions(True):
    if func.getName() == "_objc_msgSend":
        objc_msgSend_addr = func.getEntryPoint()
        break

if objc_msgSend_addr is None:
    print("Could not find objc_msgSend function")
    exit(1)
print("[*] 'objc_msgSend' found at {}".format(objc_msgSend_addr))


def rename_function(func, new_name):
    print("[*] Function at 0x{} calls objc_msgSend with selector {}".format(func.getEntryPoint(), new_name))
    final = "msgSend_" + new_name
    print("\t{} -> {}".format(func.getName(), final))
    func.setName(final, ghidra.program.model.symbol.SourceType.USER_DEFINED)


# Iterate over all functions in the current program
for func in currentProgram.getFunctionManager().getFunctions(True):
    if func.getName().startswith("FUN_"):
        
        # Get the first instruction of the function
        instr = getInstructionAt(func.getEntryPoint())
        if instr.getMnemonicString().startswith("adrp"):
            print("[*] Processing function at 0x{}".format(func.getEntryPoint()))
            selector_page_addr = instr.getOpObjects(1)[0]
            
            instr = instr.getNext()
            if instr.getMnemonicString().startswith("ldr"):
                try:
                    offset = instr.getOpObjects(1)[1]
                    selector_ptr = selector_page_addr.getValue() + offset.getValue()
                except IndexError:
                    selector_ptr = selector_page_addr.getValue()

                # Check if at selector_addr there is "addr <address>"
                selector_ptr_data = getDataAt(toAddr(selector_ptr))
                if selector_ptr_data.getMnemonicString().startswith("undefined"):
                    continue

                if selector_ptr_data.getMnemonicString() == "addr":
                    string_addr = selector_ptr_data.getValue()

                if getDataAt(string_addr) is None:
                    continue

                string_value = getDataAt(string_addr).getValue().replace(":", "_")

                # Check if following instruction is "b _objc_msgSend"
                instr = instr.getNext()
                if instr.getMnemonicString().startswith("b") and instr.getOpObjects(0)[0] == objc_msgSend_addr:
                    rename_function(func, string_value)
                    continue

                # Assert that the following instruction get the address of objc_msgSend
                if not instr.getMnemonicString().startswith("adrp"):    
                    print("[*] Unexpected instruction: {}".format(instr))
                    continue

                instr = instr.getNext()
                if not instr.getMnemonicString().startswith("add"):   
                    print("[*] Unexpected instruction: {}".format(instr))
                    continue
                
                instr = instr.getNext()
                if not instr.getMnemonicString().startswith("ldr"):
                    print("[*] Unexpected instruction: {}".format(instr))
                    continue

                instr = instr.getNext()
                if not instr.getMnemonicString().startswith("braa"):
                    print("[*] Unexpected instruction: {}".format(instr))
                    continue
                
                rename_function(func, string_value)
