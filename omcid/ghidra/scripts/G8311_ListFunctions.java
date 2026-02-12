// ListFunctions.java — Ghidra headless script
// Lists all functions in the program with their addresses and sizes.
//
// Script arguments:
//   arg[0]: output file path (Windows path)
//   arg[1]: (optional) filter substring for function names
//
// @category 8311

import ghidra.app.script.GhidraScript;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;

import java.io.FileWriter;
import java.io.PrintWriter;

public class G8311_ListFunctions extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 1) {
			println("Usage: ListFunctions.java <output_file> [filter]");
			return;
		}

		String outputPath = args[0];
		String filter = args.length > 1 ? args[1] : null;

		int count = 0;
		try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
			pw.println("# Functions in " + currentProgram.getName());
			pw.println("# Format: address  size  name");
			if (filter != null)
				pw.println("# Filter: " + filter);
			pw.println();

			FunctionIterator iter = currentProgram.getFunctionManager().getFunctions(true);
			while (iter.hasNext() && !monitor.isCancelled()) {
				Function func = iter.next();
				String name = func.getName();

				if (filter != null && !name.contains(filter))
					continue;

				long size = func.getBody().getNumAddresses();
				pw.printf("0x%08x  %6d  %s%n",
					func.getEntryPoint().getOffset(),
					size,
					name);
				count++;
			}
		}

		println("Listed " + count + " functions to: " + outputPath);
	}
}
