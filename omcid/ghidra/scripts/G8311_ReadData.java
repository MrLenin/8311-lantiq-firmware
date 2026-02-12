// G8311_ReadData.java — Read data values at specified addresses
//
// Script arguments:
//   arg[0]: output file path
//   arg[1+]: hex addresses to read (e.g., 0x436398 0x4363ac)
//
// For each address, reads 4 bytes and prints as hex uint32.
//
// @category 8311

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

import java.io.FileWriter;
import java.io.PrintWriter;

public class G8311_ReadData extends GhidraScript {

	@Override
	public void run() throws Exception {
		String[] args = getScriptArgs();
		if (args.length < 2) {
			println("Usage: G8311_ReadData.java <output_file> <addr1> [addr2] ...");
			return;
		}

		String outputPath = args[0];
		Memory memory = currentProgram.getMemory();

		try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
			pw.println("# Data values from " + currentProgram.getName());

			for (int i = 1; i < args.length; i++) {
				String addrStr = args[i];
				try {
					Address addr = currentProgram.getAddressFactory()
						.getDefaultAddressSpace().getAddress(addrStr);

					// Read 4 bytes as big-endian uint32
					byte[] bytes = new byte[4];
					memory.getBytes(addr, bytes);
					long val = ((bytes[0] & 0xFFL) << 24) |
							   ((bytes[1] & 0xFFL) << 16) |
							   ((bytes[2] & 0xFFL) << 8) |
							   (bytes[3] & 0xFFL);

					// Also try reading as a pointer and following it
					long ptrVal = val;
					String deref = "";
					try {
						Address ptrAddr = currentProgram.getAddressFactory()
							.getDefaultAddressSpace().getAddress("0x" + Long.toHexString(ptrVal));
						byte[] ptrBytes = new byte[4];
						memory.getBytes(ptrAddr, ptrBytes);
						long derefVal = ((ptrBytes[0] & 0xFFL) << 24) |
										((ptrBytes[1] & 0xFFL) << 16) |
										((ptrBytes[2] & 0xFFL) << 8) |
										(ptrBytes[3] & 0xFFL);
						deref = String.format("  -> *0x%08x = 0x%08x", ptrVal, derefVal);
					} catch (Exception e) {
						// Not a valid pointer, ignore
					}

					pw.printf("%s: 0x%08x%s%n", addrStr, val, deref);
					println(String.format("%s: 0x%08x%s", addrStr, val, deref));
				} catch (Exception e) {
					pw.printf("%s: ERROR %s%n", addrStr, e.getMessage());
				}
			}
		}

		println("Output written to: " + outputPath);
	}
}
