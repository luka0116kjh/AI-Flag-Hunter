# Ghidra Jython script. Run through analyzeHeadless with:
# -postScript extract_functions.py output.json

import json
import sys


KEYWORDS = [
    "flag",
    "secret",
    "key",
    "xor",
    "encrypt",
    "decrypt",
    "check",
    "verify",
    "strcmp",
    "memcmp",
]


def main():
    output_path = getScriptArgs()[0] if getScriptArgs() else "ghidra_result.json"
    fm = currentProgram.getFunctionManager()
    functions = []
    suspicious = []

    for function in fm.getFunctions(True):
        name = function.getName()
        entry = str(function.getEntryPoint())
        item = {"name": name, "entry": entry}
        functions.append(item)
        if any(keyword.lower() in name.lower() for keyword in KEYWORDS):
            suspicious.append(item)

    imports = []
    symbol_table = currentProgram.getSymbolTable()
    for symbol in symbol_table.getExternalSymbols():
        imports.append({"name": symbol.getName(), "address": str(symbol.getAddress())})

    result = {
        "architecture": currentProgram.getLanguage().toString(),
        "entry_point": str(currentProgram.getMinAddress()),
        "functions": functions[:1000],
        "imports": imports[:1000],
        "suspicious_functions": suspicious[:200],
        "keywords": KEYWORDS,
    }

    with open(output_path, "w") as handle:
        json.dump(result, handle, indent=2)


main()
