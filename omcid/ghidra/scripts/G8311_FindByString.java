// G8311_FindByString.java — Find and decompile functions that reference a string
//
// Script arguments:
//   arg[0]: string to search for in the binary data
//   arg[1]: output file path (Windows path)
//
// Finds all string references, traces xrefs to find calling functions,
// then decompiles each unique function.
//
// @category 8311

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.*;

public class G8311_FindByString extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			println("Usage: G8311_FindByString.java <search_string> <output_file>");
			return;
		}

		String searchStr = args[0];
		String outputPath = args[1];

		println("Searching for string: " + searchStr);

		// Find the string in memory
		Memory memory = currentProgram.getMemory();
		byte[] searchBytes = searchStr.getBytes("ASCII");

		List<Address> stringAddrs = new ArrayList<>();
		Address addr = memory.getMinAddress();
		while (addr != null) {
			addr = memory.findBytes(addr, searchBytes, null, true, monitor);
			if (addr != null) {
				stringAddrs.add(addr);
				println("  Found string at: " + addr);
				addr = addr.add(1);
			}
		}

		if (stringAddrs.isEmpty()) {
			println("String not found: " + searchStr);
			try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
				pw.println("// String not found: " + searchStr);
			}
			return;
		}

		// Find functions that reference these strings
		Set<Function> functions = new LinkedHashSet<>();
		for (Address sAddr : stringAddrs) {
			// Check references TO this address (and nearby, since string
			// refs may point to start of the string data)
			for (long offset = -4; offset <= 4; offset++) {
				Address checkAddr = sAddr.add(offset);
				ReferenceIterator refs = currentProgram.getReferenceManager()
					.getReferencesTo(checkAddr);
				while (refs.hasNext()) {
					Reference ref = refs.next();
					Address fromAddr = ref.getFromAddress();
					Function func = getFunctionContaining(fromAddr);
					if (func != null) {
						functions.add(func);
						println("  Xref from " + fromAddr + " in " + func.getName());
					}
				}
			}
		}

		if (functions.isEmpty()) {
			println("No function references found for string: " + searchStr);
			try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
				pw.println("// String found but no xrefs: " + searchStr);
				for (Address sa : stringAddrs) {
					pw.println("// String at: " + sa);
				}
			}
			return;
		}

		// Decompile each function
		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);

		try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
			pw.println("// Decompiled from: " + currentProgram.getName());
			pw.println("// String search: " + searchStr);
			pw.println("// Functions found: " + functions.size());
			pw.println();

			for (Function func : functions) {
				pw.println("// ============================================================");
				pw.println("// Function: " + func.getName());
				pw.println("// Address:  " + func.getEntryPoint());
				pw.println("// Size:     " + func.getBody().getNumAddresses() + " bytes");
				pw.println("// ============================================================");
				pw.println();

				DecompileResults results = decomp.decompileFunction(func, 120, monitor);
				if (results.decompileCompleted()) {
					pw.println(results.getDecompiledFunction().getC());
				} else {
					pw.println("// DECOMPILATION FAILED: " + results.getErrorMessage());
				}
				pw.println();
			}
		}

		decomp.dispose();
		println("Output written to: " + outputPath);
	}
}
