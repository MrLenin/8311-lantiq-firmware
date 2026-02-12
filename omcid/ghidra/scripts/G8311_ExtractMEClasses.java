// G8311_ExtractMEClasses.java — Extract ME class IDs from me_def_class_array
//
// Script arguments:
//   arg[0]: output file path
//   arg[1]: address of me_def_class_array 
//   arg[2]: number of entries
//
// @category 8311

import ghidra.app.script.GhidraScript;
import ghidra.program.model.address.Address;
import ghidra.program.model.mem.Memory;

import java.io.FileWriter;
import java.io.PrintWriter;

public class G8311_ExtractMEClasses extends GhidraScript {

    @Override
    public void run() throws Exception {
        String[] args = getScriptArgs();
        if (args.length < 3) {
            println("Usage: G8311_ExtractMEClasses.java <output_file> <array_addr> <count>");
            return;
        }

        String outputPath = args[0];
        long arrayAddr = Long.decode(args[1]);
        int count = Integer.parseInt(args[2]);

        Memory memory = currentProgram.getMemory();

        try (PrintWriter pw = new PrintWriter(new FileWriter(outputPath))) {
            pw.println("# ME class IDs from me_def_class_array");
            pw.println("# Format: index  class_id  struct_addr  name_addr  name_string");
            pw.println("# Array at: 0x" + Long.toHexString(arrayAddr) + ", count: " + count);
            pw.println();

            for (int i = 0; i < count; i++) {
                Address ptrAddr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(
                        "0x" + Long.toHexString(arrayAddr + i * 4));

                // Read the pointer (4 bytes, big-endian MIPS)
                byte[] ptrBytes = new byte[4];
                memory.getBytes(ptrAddr, ptrBytes);
                long structAddr = ((ptrBytes[0] & 0xFFL) << 24) |
                                  ((ptrBytes[1] & 0xFFL) << 16) |
                                  ((ptrBytes[2] & 0xFFL) << 8) |
                                  (ptrBytes[3] & 0xFFL);

                // Read class_id (first 2 bytes of the struct, big-endian)
                Address meAddr = currentProgram.getAddressFactory()
                    .getDefaultAddressSpace().getAddress(
                        "0x" + Long.toHexString(structAddr));
                byte[] idBytes = new byte[2];
                memory.getBytes(meAddr, idBytes);
                int classId = ((idBytes[0] & 0xFF) << 8) | (idBytes[1] & 0xFF);

                // The name is stored at a specific offset in the struct.
                // In the me_class struct, after class_id (2 bytes + 2 padding),
                // come 16 me_attr structs. Let me also try to read the
                // 'name' field which is in the 'desc' sub-struct at the end.
                // For now, just output the class_id.
                
                // Also try to read the "desc.name" - it's a pointer at a
                // known offset. From the decompiled code, puVar7 + 0x316 
                // was used as a name string (25 chars). Let me read that.
                // 0x316 in ushort units = 0x62c in bytes from struct start
                String nameStr = "?";
                try {
                    Address nameAddr = currentProgram.getAddressFactory()
                        .getDefaultAddressSpace().getAddress(
                            "0x" + Long.toHexString(structAddr + 0x62c));
                    byte[] nameBytes = new byte[30];
                    memory.getBytes(nameAddr, nameBytes);
                    // Find null terminator
                    int len = 0;
                    for (int j = 0; j < nameBytes.length; j++) {
                        if (nameBytes[j] == 0) break;
                        len++;
                    }
                    nameStr = new String(nameBytes, 0, len, "ASCII");
                } catch (Exception e) {
                    nameStr = "?(" + e.getMessage() + ")";
                }

                pw.printf("%3d  %5d  0x%08x  %s%n", i, classId, structAddr, nameStr);
            }
        }

        println("Extracted " + count + " ME class IDs to: " + outputPath);
    }
}
