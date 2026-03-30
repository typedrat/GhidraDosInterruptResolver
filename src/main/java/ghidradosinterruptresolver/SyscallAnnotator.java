package ghidradosinterruptresolver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.data.WordDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.BookmarkType;
import ghidra.program.model.listing.CommentType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.Msg;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;

import ghidradosinterruptresolver.model.InterruptEntry;
import ghidradosinterruptresolver.model.RegisterValue;
import ghidradosinterruptresolver.model.ReturnBranch;

/**
 * Applies annotations (overlay functions, comments, bookmarks, references)
 * for resolved interrupt calls. Interrupt functions are created in an
 * overlay memory block filled with RET instructions, with register-based
 * prototypes so the decompiler can reason about input/output registers.
 */
public class SyscallAnnotator {

    private static final String OVERLAY_SPACE_NAME = "INT";
    private static final String OVERLAY_DESCRIPTION = "DOS Interrupt Function Stubs";
    private static final String OVERLAY_SOURCE = "DosSyscallAnalyzer";
    private static final int OVERLAY_SIZE = 0x10000;

    // Configuration flags
    private final boolean addPlateComments;
    private final boolean addPrePostComments;
    private final boolean createOverlayFunctions;
    private final boolean addBookmarks;
    private final boolean addReferences;

    // Overlay space state
    private AddressSpace overlaySpace;
    private final Map<String, Address> functionMap = new HashMap<>();
    private long nextOverlayOffset = 0;

    public SyscallAnnotator(boolean addPlateComments, boolean addPrePostComments,
                            boolean createOverlayFunctions, boolean addBookmarks,
                            boolean addReferences) {
        this.addPlateComments = addPlateComments;
        this.addPrePostComments = addPrePostComments;
        this.createOverlayFunctions = createOverlayFunctions;
        this.addBookmarks = addBookmarks;
        this.addReferences = addReferences;
    }

    // -----------------------------------------------------------------------
    // Overlay Space Lifecycle
    // -----------------------------------------------------------------------

    public boolean initOverlaySpace(Program program) {
        overlaySpace = program.getAddressFactory().getAddressSpace(OVERLAY_SPACE_NAME);
        if (overlaySpace != null) {
            rebuildStateFromExistingOverlay(program);
            return true;
        }

        if (!program.hasExclusiveAccess()) {
            Msg.warn(this, "Cannot create overlay space without exclusive access");
            return false;
        }

        // Overlay on the default (RAM) space so it inherits the correct
        // processor context for x86 disassembly and decompilation.
        AddressSpace defaultSpace = program.getAddressFactory().getDefaultAddressSpace();

        // Fill with 0xC3 (RET near) so each function address has a valid
        // instruction the decompiler can analyze.
        AddInitializedMemoryBlockCmd cmd = new AddInitializedMemoryBlockCmd(
                OVERLAY_SPACE_NAME, OVERLAY_DESCRIPTION, OVERLAY_SOURCE,
                defaultSpace.getAddress(0x0), OVERLAY_SIZE,
                true, false, true, false, (byte) 0xC3, true);

        if (!cmd.applyTo(program)) {
            Msg.warn(this, "Failed to create overlay memory block: " + cmd.getStatusMsg());
            return false;
        }

        overlaySpace = program.getAddressFactory().getAddressSpace(OVERLAY_SPACE_NAME);
        return overlaySpace != null;
    }

    private void rebuildStateFromExistingOverlay(Program program) {
        FunctionIterator funcIter = program.getFunctionManager()
                .getFunctions(overlaySpace.getMinAddress(), true);
        while (funcIter.hasNext()) {
            Function func = funcIter.next();
            Address addr = func.getEntryPoint();
            if (!addr.getAddressSpace().equals(overlaySpace)) {
                break;
            }
            functionMap.put(func.getName(), addr);
            long offset = addr.getOffset() + 1;
            if (offset > nextOverlayOffset) {
                nextOverlayOffset = offset;
            }
        }
    }

    // -----------------------------------------------------------------------
    // Main Annotation Entry Point
    // -----------------------------------------------------------------------

    public void annotate(Program program, Address intAddr, int interruptNumber,
                         InterruptEntry entry) {
        String intHex = String.format("%02X", interruptNumber);

        if (addPlateComments) {
            applyPlateComment(program, intAddr, intHex, entry);
        }

        if (addPrePostComments) {
            applyCombinedComment(program, intAddr, intHex, entry);
        }

        Address overlayAddr = null;
        if (createOverlayFunctions) {
            overlayAddr = getOrCreateOverlayFunction(program, intHex, entry);
        }

        if (addBookmarks) {
            applyBookmark(program, intAddr, intHex, entry);
        }

        if (addReferences && overlayAddr != null) {
            applyReference(program, intAddr, overlayAddr);
        }
    }

    // -----------------------------------------------------------------------
    // Plate Comment
    // -----------------------------------------------------------------------

    private void applyPlateComment(Program program, Address intAddr,
                                   String intHex, InterruptEntry entry) {
        String existing = program.getListing().getComment(CommentType.PLATE, intAddr);
        if (existing != null && !existing.isEmpty()) {
            return;
        }

        String title = entry.getTitle() != null ? entry.getTitle() : "Unknown";
        String category = entry.getCategory() != null ? entry.getCategory() : "?";
        String id = entry.getId() != null ? entry.getId() : "?";
        String categoryLabel = expandCategoryLabel(category);

        String text;
        if (addPrePostComments) {
            // Full header is already in the PRE comment; keep plate concise
            text = String.format("INT %sh - %s", intHex, title);
        } else {
            text = String.format("INT %sh - %s\nCategory: %s (%s)  |  ID: %s",
                    intHex, title, category, categoryLabel, id);
        }

        program.getListing().setComment(intAddr, CommentType.PLATE, text);
    }

    private static String expandCategoryLabel(String category) {
        if (category == null || category.isEmpty()) {
            return "Unknown";
        }
        switch (category.toUpperCase(Locale.ROOT)) {
            case "D": return "DOS";
            case "B": return "BIOS";
            case "V": return "Video";
            case "K": return "Keyboard";
            case "S": return "Serial";
            case "P": return "Printer";
            case "T": return "Timer";
            case "M": return "Mouse";
            case "N": return "Network";
            case "X": return "Extended";
            default:  return category;
        }
    }

    // -----------------------------------------------------------------------
    // Combined Input + Returns Comment (PRE comment — visible in decompiler)
    // -----------------------------------------------------------------------

    private void applyCombinedComment(Program program, Address intAddr,
                                     String intHex, InterruptEntry entry) {
        String existing = program.getListing().getComment(CommentType.PRE, intAddr);
        if (existing != null && !existing.isEmpty()) {
            return;
        }

        List<RegisterValue> inputs = entry.getInputRegisters();
        List<ReturnBranch> returns = entry.getReturns();
        boolean hasInputs = inputs != null && !inputs.isEmpty();
        boolean hasReturns = returns != null && !returns.isEmpty();

        StringBuilder sb = new StringBuilder();

        // Header (same info as plate comment — visible in decompiler too)
        String title = entry.getTitle() != null ? entry.getTitle() : "Unknown";
        String category = entry.getCategory() != null ? entry.getCategory() : "?";
        String id = entry.getId() != null ? entry.getId() : "?";
        String categoryLabel = expandCategoryLabel(category);
        sb.append(String.format("INT %sh - %s", intHex, title));
        sb.append(String.format("\nCategory: %s (%s)  |  ID: %s", category, categoryLabel, id));

        if (hasInputs) {
            sb.append("\nInput:");
            for (RegisterValue rv : inputs) {
                sb.append('\n');
                formatRegisterValue(sb, rv, "  ");
            }
        }

        if (hasReturns) {
            if (hasInputs) {
                sb.append('\n');
            }
            sb.append("Returns:");
            for (ReturnBranch branch : returns) {
                String condition = branch.getCondition();
                String condDesc = branch.getConditionDescription();
                List<RegisterValue> regs = branch.getRegisters();
                List<String> rawLines = branch.getRawLines();
                boolean hasCondition = condition != null;
                String regIndent = hasCondition ? "    " : "  ";

                if (hasCondition) {
                    sb.append("\n  ").append(condition);
                    if (condDesc != null) {
                        sb.append(" (").append(condDesc).append(')');
                    }
                    sb.append(':');
                }

                if (regs != null && !regs.isEmpty()) {
                    for (RegisterValue rv : regs) {
                        sb.append('\n');
                        formatRegisterValue(sb, rv, regIndent);
                    }
                } else if (rawLines != null && !rawLines.isEmpty()) {
                    for (String line : rawLines) {
                        sb.append('\n').append(regIndent).append(line);
                    }
                }
            }
        }

        program.getListing().setComment(intAddr, CommentType.PRE, sb.toString());
    }

    private void formatRegisterValue(StringBuilder sb, RegisterValue rv, String indent) {
        String reg = rv.getReg() != null ? rv.getReg() : "?";
        String operator = rv.getOperator() != null ? rv.getOperator() : "=";
        String value = rv.getValue();
        String description = rv.getDescription();

        sb.append(indent).append(reg).append(' ').append(operator).append(' ');

        if (value != null) {
            sb.append(value);
            if (description != null) {
                sb.append(" (").append(description).append(')');
            }
        } else if (description != null) {
            sb.append(description);
        }
    }

    // -----------------------------------------------------------------------
    // Overlay Functions + Register Prototypes
    // -----------------------------------------------------------------------

    private Address getOrCreateOverlayFunction(Program program, String intHex,
                                                InterruptEntry entry) {
        if (overlaySpace == null) {
            return null;
        }

        String funcName = buildFunctionName(intHex, entry.getTitle(), entry.getFunction());

        Address existing = functionMap.get(funcName);
        if (existing != null) {
            return existing;
        }

        if (nextOverlayOffset >= OVERLAY_SIZE) {
            Msg.warn(this, "Overlay space exhausted; cannot create: " + funcName);
            return null;
        }

        Address overlayAddr = overlaySpace.getAddress(nextOverlayOffset);
        nextOverlayOffset++;

        try {
            Function existingFunc = program.getFunctionManager().getFunctionAt(overlayAddr);
            if (existingFunc == null) {
                // Disassemble the RET byte so the function has a valid instruction
                DisassembleCommand disCmd = new DisassembleCommand(
                        overlayAddr, new AddressSet(overlayAddr, overlayAddr), true);
                disCmd.applyTo(program);

                Function func = program.getFunctionManager().createFunction(
                        funcName, overlayAddr,
                        new AddressSet(overlayAddr, overlayAddr),
                        SourceType.ANALYSIS);

                if (func != null) {
                    if (entry.getTitle() != null
                            && entry.getTitle().toUpperCase(Locale.ROOT).contains("TERMINATE")) {
                        func.setNoReturn(true);
                    }
                    applyFunctionPrototype(program, func, entry);
                }
            }
            functionMap.put(funcName, overlayAddr);
            return overlayAddr;
        } catch (Exception e) {
            Msg.warn(this, "Failed to create overlay function '" + funcName
                    + "' at " + overlayAddr + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Apply a register-based function prototype so the decompiler
     * understands which registers are inputs and outputs.
     *
     * <p>The function selector register (matching the entry's {@code function}
     * field) is skipped. All other inputs become parameters.
     *
     * <p>Multiple return registers are captured as a struct with named fields
     * and register-name comments.
     */
    private void applyFunctionPrototype(Program program, Function func, InterruptEntry entry) {
        List<RegisterValue> inputs = entry.getInputRegisters();
        List<ReturnBranch> returns = entry.getReturns();
        String functionCode = entry.getFunction();

        // --- Input parameters ---
        List<Parameter> params = new ArrayList<>();
        if (inputs != null) {
            for (RegisterValue rv : inputs) {
                if (isFunctionSelector(rv, functionCode)) {
                    continue;
                }
                String regName = rv.getReg();
                if (regName == null) {
                    continue;
                }

                VariableStorage storage = resolveRegisterStorage(program, regName);
                if (storage == null) {
                    continue;
                }

                DataType dt = getDataTypeForStorage(storage, rv.getOperator());
                String paramName = buildIdentifierName(rv, "param");

                try {
                    params.add(new ParameterImpl(paramName, dt, storage, program));
                } catch (InvalidInputException e) {
                    Msg.debug(this, "Skipping parameter " + paramName + ": " + e.getMessage());
                }
            }
        }

        // --- Return value ---
        DataType returnType = VoidDataType.dataType;
        VariableStorage returnStorage = VariableStorage.VOID_STORAGE;

        if (returns != null) {
            ReturnBranch bestBranch = pickReturnBranch(returns);
            if (bestBranch != null) {
                List<RegisterValue> retRegs = bestBranch.getRegisters();
                if (retRegs != null && !retRegs.isEmpty()) {
                    List<VariableStorage> retStorages = new ArrayList<>();
                    List<String> retNames = new ArrayList<>();
                    List<DataType> retTypes = new ArrayList<>();
                    List<String> retRegNames = new ArrayList<>();

                    for (RegisterValue rv : retRegs) {
                        String regName = rv.getReg();
                        if (regName == null) {
                            continue;
                        }
                        VariableStorage s = resolveRegisterStorage(program, regName);
                        if (s == null) {
                            continue;
                        }
                        retStorages.add(s);
                        retNames.add(buildIdentifierName(rv, "field"));
                        retTypes.add(getDataTypeForStorage(s, rv.getOperator()));
                        retRegNames.add(regName);
                    }

                    if (retStorages.size() == 1) {
                        returnType = retTypes.get(0);
                        returnStorage = retStorages.get(0);
                    } else if (retStorages.size() > 1) {
                        try {
                            returnStorage = buildCompositeStorage(program, retStorages);
                            returnType = buildReturnStruct(program, func.getName(),
                                    retNames, retTypes, retRegNames);
                        } catch (Exception e) {
                            Msg.warn(this, "Failed to build composite return for "
                                    + func.getName() + ": " + e.getMessage());
                        }
                    }
                }
            }
        }

        try {
            func.setCustomVariableStorage(true);
            func.setReturn(returnType, returnStorage, SourceType.ANALYSIS);
            func.replaceParameters(params,
                    Function.FunctionUpdateType.CUSTOM_STORAGE,
                    true, SourceType.ANALYSIS);
        } catch (InvalidInputException | DuplicateNameException e) {
            Msg.warn(this, "Failed to set prototype for " + func.getName()
                    + ": " + e.getMessage());
        }
    }

    /**
     * Determine whether an input register is the function selector.
     */
    private boolean isFunctionSelector(RegisterValue rv, String functionCode) {
        if (rv.getValue() == null || functionCode == null) {
            return false;
        }
        String reg = rv.getReg();
        if (reg == null) {
            return false;
        }
        String val = rv.getValue().replaceAll("[hH]$", "").toUpperCase(Locale.ROOT);
        String funcUpper = functionCode.toUpperCase(Locale.ROOT);
        String regUpper = reg.toUpperCase(Locale.ROOT);

        if (regUpper.equals("AH") && funcUpper.length() == 2 && val.equals(funcUpper)) {
            return true;
        }
        if (regUpper.equals("AX") && funcUpper.length() == 4 && val.equals(funcUpper)) {
            return true;
        }
        if (regUpper.equals("AL") && val.equals(funcUpper)) {
            return true;
        }
        return false;
    }

    /**
     * Pick the best return branch — prefer unconditional, then CF clear (success).
     */
    private ReturnBranch pickReturnBranch(List<ReturnBranch> returns) {
        ReturnBranch unconditional = null;
        ReturnBranch success = null;

        for (ReturnBranch branch : returns) {
            String cond = branch.getCondition();
            if (cond == null) {
                if (unconditional == null) {
                    unconditional = branch;
                }
            } else if (cond.toLowerCase(Locale.ROOT).contains("clear")) {
                if (success == null) {
                    success = branch;
                }
            }
        }

        if (unconditional != null && unconditional.getRegisters() != null
                && !unconditional.getRegisters().isEmpty()) {
            return unconditional;
        }
        if (success != null && success.getRegisters() != null
                && !success.getRegisters().isEmpty()) {
            return success;
        }
        for (ReturnBranch branch : returns) {
            if (branch.getRegisters() != null && !branch.getRegisters().isEmpty()) {
                return branch;
            }
        }
        return null;
    }

    private VariableStorage buildCompositeStorage(Program program,
                                                   List<VariableStorage> storages)
            throws Exception {
        List<Varnode> allVarnodes = new ArrayList<>();
        for (VariableStorage s : storages) {
            for (Varnode vn : s.getVarnodes()) {
                allVarnodes.add(vn);
            }
        }
        return new VariableStorage(program, allVarnodes.toArray(new Varnode[0]));
    }

    private DataType buildReturnStruct(Program program, String funcName,
                                        List<String> fieldNames,
                                        List<DataType> fieldTypes,
                                        List<String> regNames) {
        String structName = funcName + "_RESULT";
        CategoryPath category = new CategoryPath("/DOS_INTERRUPTS");
        DataTypeManager dtm = program.getDataTypeManager();

        DataType existing = dtm.getDataType(category, structName);
        if (existing != null) {
            return existing;
        }

        StructureDataType struct = new StructureDataType(category, structName, 0, dtm);
        for (int i = 0; i < fieldNames.size(); i++) {
            struct.add(fieldTypes.get(i), fieldNames.get(i), regNames.get(i));
        }

        return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
    }

    // -----------------------------------------------------------------------
    // Register Storage Helpers
    // -----------------------------------------------------------------------

    private VariableStorage resolveRegisterStorage(Program program, String regName) {
        if (regName == null || regName.isEmpty()) {
            return null;
        }

        String upper = regName.toUpperCase(Locale.ROOT);
        if (upper.equals("CF") || upper.equals("ZF") || upper.equals("SF")
                || upper.equals("OF") || upper.equals("DF") || upper.equals("IF")) {
            return null;
        }

        if (regName.contains(":")) {
            String[] parts = regName.split(":");
            if (parts.length == 2) {
                Register segReg = program.getRegister(parts[0].trim());
                Register offReg = program.getRegister(parts[1].trim());
                if (segReg != null && offReg != null) {
                    try {
                        return new VariableStorage(program, offReg, segReg);
                    } catch (Exception e) {
                        return null;
                    }
                }
            }
            return null;
        }

        Register reg = program.getRegister(regName);
        if (reg == null) {
            return null;
        }
        try {
            return new VariableStorage(program, reg);
        } catch (Exception e) {
            return null;
        }
    }

    private DataType getDataTypeForStorage(VariableStorage storage, String operator) {
        if ("->".equals(operator)) {
            return new PointerDataType();
        }
        int size = storage.size();
        if (size <= 1) {
            return ByteDataType.dataType;
        }
        if (size <= 2) {
            return WordDataType.dataType;
        }
        return new PointerDataType();
    }

    private String buildIdentifierName(RegisterValue rv, String fallback) {
        String desc = rv.getDescription();
        if (desc != null && !desc.isEmpty()) {
            String name = desc.replaceAll("[^A-Za-z0-9_ ]", "").trim();
            name = name.replaceAll("\\s+", "_");
            if (name.length() > 30) {
                name = name.substring(0, 30);
            }
            name = name.replaceAll("_+$", "");
            if (!name.isEmpty() && Character.isJavaIdentifierStart(name.charAt(0))) {
                return name;
            }
        }
        String reg = rv.getReg();
        return reg != null ? reg.replace(":", "_") : fallback;
    }

    static String buildFunctionName(String intHex, String title, String functionCode) {
        String base;
        if (title == null || title.isEmpty()) {
            base = "UNKNOWN";
        } else {
            int lastSep = title.lastIndexOf(" - ");
            if (lastSep >= 0) {
                base = title.substring(lastSep + 3).trim();
            } else {
                base = title.trim();
            }
        }

        base = base.replaceAll("[^A-Za-z0-9]", "_");
        base = base.replaceAll("_+", "_");
        base = base.replaceAll("^_+|_+$", "");

        if (base.isEmpty()) {
            base = "UNKNOWN";
        }

        StringBuilder name = new StringBuilder("INT").append(intHex).append("h");
        if (functionCode != null && !functionCode.isEmpty()) {
            name.append('_').append(functionCode);
        }
        name.append('_').append(base);
        return name.toString();
    }

    // -----------------------------------------------------------------------
    // Bookmarks
    // -----------------------------------------------------------------------

    private void applyBookmark(Program program, Address intAddr,
                               String intHex, InterruptEntry entry) {
        String title = entry.getTitle() != null ? entry.getTitle() : "Unknown";
        String description = String.format("INT %sh - %s", intHex, title);

        program.getBookmarkManager().setBookmark(
                intAddr, BookmarkType.ANALYSIS, "DOS Interrupt", description);
    }

    // -----------------------------------------------------------------------
    // References
    // -----------------------------------------------------------------------

    private void applyReference(Program program, Address intAddr, Address overlayAddr) {
        // DATA reference provides clickable navigation in the Listing without
        // injecting a function call into the decompiler output (which would
        // appear alongside the un-removable swi() line).
        program.getReferenceManager().addMemoryReference(
                intAddr, overlayAddr,
                RefType.DATA, SourceType.ANALYSIS, Reference.MNEMONIC);
    }
}
