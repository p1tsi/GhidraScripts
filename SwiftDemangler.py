#Demangles Swift class, function, and variable names
#@author p1tsi
#@category Swift

# NOTES:
# Requires Swift to be installed on the machine
# Takes some time to run for larger applications
# Optimized (hopefully) version of https://github.com/LaurieWired/iOS_Reverse_Engineering/blob/main/SwiftNameDemangler.py

from ghidra.program.model.listing import Function
from ghidra.program.model.symbol import SymbolType
from java.lang import System
import subprocess

DEMANGLE_CMD = 'xcrun swift-demangle --simplified --compact' if 'mac' in System.getProperty("os.name").lower() else 'swift-demangle --simplified --compact'

def demangle(items):
    names = list(map(lambda x: x.getName(), items))
    input = "\n".join(names)
    proc = subprocess.Popen(DEMANGLE_CMD, shell=True, stdout=subprocess.PIPE, stdin=subprocess.PIPE)
    out, err = proc.communicate(input)
    return out.split("\n")[:-1]

### FUNCTIONS
swift_functions = list(filter(lambda x:
                                x.getParentNamespace().getName() == 'Global' or x.getParentNamespace().getName() == '__stub_helper' or x.getParentNamespace().getName() == '__stubs'
                                and not x.getName().startswith('FUN_') 
                                and '[' not in x.getName()
                                , currentProgram.getFunctionManager().getFunctionsNoStubs(True)))

out_func = demangle(swift_functions)

for i, func in enumerate(swift_functions):
		new_name = out_func[i].replace(" ", "_").replace("<", "_").replace(">", "_").replace("=", "")
		if func.getName() != new_name:
				print("OLD: {} - NEW: {}".format(func, new_name))
				func.setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)

### SYMBOLS 
swift_symbols = list(filter(lambda x:
                                x.getSymbolType() == SymbolType.LABEL 
                                and not x.getName().startswith("LAB_")
                                and not x.getName().startswith("DAT_")
                                and not x.getName().startswith("FUN_")
                                and not x.getName().startswith("case")
                                and not x.getName().startswith("switch")
                                , currentProgram.getSymbolTable().getAllSymbols(True)))

out_syms = demangle(swift_symbols)

for i, sym in enumerate(swift_symbols):
		new_name = out_syms[i].replace(" ", "_").replace("<", "_").replace(">", "_").replace("=", "")
		if sym.getName() != new_name:
				print("OLD: {} - NEW: {}".format(sym, new_name))
				sym.setName(new_name, ghidra.program.model.symbol.SourceType.USER_DEFINED)
