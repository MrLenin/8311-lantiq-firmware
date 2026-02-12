// DecompileFunction.java — Ghidra headless script
// Decompiles functions matching a query and writes C output to a file.
//
// Script arguments (passed via -scriptPath):
//   arg[0]: query — hex address (0x...) or substring to match in function name
//   arg[1]: output file path (Windows path)
//   arg[2]: (optional) "all" to dump ALL functions containing the substring
//
// Usage:
//   analyzeHeadless <project> <name> -process <binary> \
//     -scriptPath <dir> -postScript DecompileFunction.java "0x438b4c" "C:\temp\out.c"
//
// @category 8311

import ghidra.app.decompiler.DecompInterface;
import ghidra.app.decompiler.DecompileResults;
import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.address.Address;

import java.io.FileWriter;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.List;

public class G8311_Decompile extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			println("Usage: DecompileFunction.java <query> <output_file> [all]");
			println("  query: hex address (0x...) or function name substring");
			println("  output_file: path to write decompiled C code");
			println("  all: if present, match ALL functions containing substring");
			return;
		}

		String query = args[0];
		String outputPath = args[1];
		boolean matchAll = args.length > 2 && args[2].equalsIgnoreCase("all");

		List<Function> functions = findFunctions(query, matchAll);

		if (functions.isEmpty()) {
			println("No functions found matching: " + query);
			try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
				pw.println("// No functions found matching: " + query);
			}
			return;
		}

		DecompInterface decomp = new DecompInterface();
		decomp.openProgram(currentProgram);

		try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
			pw.println("// Decompiled from: " + currentProgram.getName());
			pw.println("// Query: " + query);
			pw.println("// Functions matched: " + functions.size());
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

				println("Decompiled: " + func.getName() + " @ " + func.getEntryPoint());
			}
		}

		decomp.dispose();
		println("Output written to: " + outputPath);
	}

	private List<Function> findFunctions(String query, boolean matchAll) {
		List<Function> result = new ArrayList<>();

		// Try as hex address first
		if (query.startsWith("0x") || query.startsWith("0X")) {
			try {
				Address addr = currentProgram.getAddressFactory()
					.getDefaultAddressSpace()
					.getAddress(query);
				Function func = getFunctionAt(addr);
				if (func == null) {
					// Try getting the function containing this address
					func = getFunctionContaining(addr);
				}
				if (func != null) {
					result.add(func);
					return result;
				}
			} catch (Exception e) {
				// Fall through to name search
			}
		}

		// Search by name substring
		FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
		while (iter.hasNext() && !monitor.isCancelled()) {
			Function func = iter.next();
			if (func.getName().contains(query)) {
				result.add(func);
				if (!matchAll) {
					break;  // Return first match only
				}
			}
		}

		return result;
	}
}
