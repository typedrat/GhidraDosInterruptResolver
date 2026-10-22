package ghidradosinterruptresolver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

import ghidra.app.cmd.disassemble.DisassembleCommand;
import ghidra.app.cmd.memory.AddInitializedMemoryBlockCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.CharDataType;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictHandler;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.DWordDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.Undefined;
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
import ghidra.program.model.symbol.ReferenceManager;
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

    /** Program exits: INT 20h, INT 21h AH=00h/31h/4Ch, INT 27h. */
    private static final Set<String> TERMINATING_CALLS =
            Set.of("20", "21/00", "21/31", "21/4C", "27");

    private static final int MAX_LISTED_CANDIDATES = 5;

    // Configuration flags
    private final boolean addPlateComments;
    private final boolean addPrePostComments;
    private final boolean createOverlayFunctions;
    private final boolean addBookmarks;
    private final boolean addReferences;
    private final boolean overrideCalls;

    // Overlay space state
    private AddressSpace overlaySpace;
    private final Map<String, Address> functionMap = new HashMap<>();
    private long nextOverlayOffset = 0;

    public SyscallAnnotator(boolean addPlateComments, boolean addPrePostComments,
                            boolean createOverlayFunctions, boolean addBookmarks,
                            boolean addReferences, boolean overrideCalls) {
        this.addPlateComments = addPlateComments;
        this.addPrePostComments = addPrePostComments;
        this.createOverlayFunctions = createOverlayFunctions;
        this.addBookmarks = addBookmarks;
        this.addReferences = addReferences;
        this.overrideCalls = overrideCalls;
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
        String funcName = buildFunctionName(intHex, entry.getTitle(), entry.getFunction());
        return getOrCreateStub(program, funcName, func -> {
            if (isNoReturn(intHex, entry)) {
                func.setNoReturn(true);
            }
            applyFunctionPrototype(program, func, entry);
        });
    }

    /**
     * Creates (once per name) a RET stub in the overlay and runs
     * {@code init} on the new function.
     */
    private Address getOrCreateStub(Program program, String funcName,
                                    StubInitializer init) {
        if (overlaySpace == null) {
            return null;
        }

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
                    init.apply(func);
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

    @FunctionalInterface
    private interface StubInitializer {
        void apply(Function func) throws Exception;
    }

    /**
     * Gives an INT with no matching entry a call override to a per-vector
     * stub that takes and returns nothing. When the swi() fixup is
     * installed, an INT left without an override would decompile as a call
     * through the raw vector-table address.
     *
     * @param ahValue the resolved AH value, or {@code null} if unknown
     */
    public void annotateUnresolved(Program program, Address intAddr, int interruptNumber,
                                   Long ahValue, Long alValue,
                                   List<InterruptEntry> candidates) {
        String intHex = String.format("%02X", interruptNumber);
        if (addPlateComments && !candidates.isEmpty()) {
            applyCandidatesComment(program, intAddr, intHex, ahValue, alValue, candidates);
        }
        if (!createOverlayFunctions || !addReferences || !overrideCalls) {
            return;
        }
        String funcName = ahValue != null
                ? String.format("INT%sh_%02X_UNKNOWN", intHex, ahValue & 0xFF)
                : "INT" + intHex + "h_UNKNOWN";
        Address stub = getOrCreateStub(program, funcName, func -> {
            func.setCustomVariableStorage(true);
            func.setReturn(VoidDataType.dataType, VariableStorage.VOID_STORAGE,
                    SourceType.ANALYSIS);
            func.replaceParameters(List.of(), Function.FunctionUpdateType.CUSTOM_STORAGE,
                    true, SourceType.ANALYSIS);
        });
        if (stub != null) {
            applyReference(program, intAddr, stub);
        }
    }

    private void applyCandidatesComment(Program program, Address intAddr, String intHex,
                                        Long ahValue, Long alValue,
                                        List<InterruptEntry> candidates) {
        String existing = program.getListing().getComment(CommentType.PLATE, intAddr);
        if (existing != null && !existing.isEmpty()) {
            return;
        }

        StringBuilder sb = new StringBuilder("INT ").append(intHex).append('h');
        if (ahValue != null && alValue != null) {
            sb.append(String.format(" AX=%02X%02Xh", ahValue & 0xFF, alValue & 0xFF));
        } else if (ahValue != null) {
            sb.append(String.format(" AH=%02Xh", ahValue & 0xFF));
        }
        sb.append(" - unresolved, possibly:");
        int shown = Math.min(candidates.size(), MAX_LISTED_CANDIDATES);
        for (InterruptEntry candidate : candidates.subList(0, shown)) {
            sb.append("\n  ").append(candidate.getTitle() != null ? candidate.getTitle() : "?");
        }
        if (candidates.size() > shown) {
            sb.append("\n  (").append(candidates.size() - shown).append(" more)");
        }
        program.getListing().setComment(intAddr, CommentType.PLATE, sb.toString());
    }

    /**
     * Whether a call never returns to its caller. RBIL only sometimes says
     * "never returns" (DOS's own exit calls lack it), and matching on titles
     * would also catch calls like "TERMINATE DIRECTORY SEARCH", so the DOS
     * exits are listed explicitly as {@code INT} or {@code INT/function}.
     */
    static boolean isNoReturn(String intHex, InterruptEntry entry) {
        String function = entry.getFunction();
        String key = function == null || function.isEmpty()
                ? intHex
                : intHex + "/" + function.toUpperCase(Locale.ROOT);
        if (TERMINATING_CALLS.contains(key)) {
            return true;
        }
        for (ReturnBranch branch : entry.getReturns()) {
            for (String line : branch.getRawLines()) {
                if (line != null && line.toLowerCase(Locale.ROOT).contains("never return")) {
                    return true;
                }
            }
            for (RegisterValue rv : branch.getRegisters()) {
                String desc = rv.getDescription();
                if (desc != null && desc.toLowerCase(Locale.ROOT).contains("never return")) {
                    return true;
                }
            }
        }
        return false;
    }

    /**
     * Apply a register-based function prototype so the decompiler
     * understands which registers are inputs and outputs.
     *
     * <p>Inputs pinned to constants are skipped. All other inputs become
     * parameters.
     *
     * <p>Multiple return registers are captured as a struct with named fields
     * and register-name comments.
     */
    private void applyFunctionPrototype(Program program, Function func, InterruptEntry entry) {
        List<RegisterValue> inputs = entry.getInputRegisters();
        List<ReturnBranch> returns = entry.getReturns();

        // --- Input parameters ---
        List<Parameter> params = new ArrayList<>();
        if (inputs != null) {
            for (RegisterValue rv : inputs) {
                if (isFunctionSelector(rv)) {
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

                DataType dt = getDataTypeForStorage(program, storage, rv);
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
            List<VariableStorage> retStorages = new ArrayList<>();
            List<String> retNames = new ArrayList<>();
            List<DataType> retTypes = new ArrayList<>();
            List<String> retRegNames = new ArrayList<>();

            ReturnBranch bestBranch = pickReturnBranch(returns);
            if (bestBranch != null) {
                for (RegisterValue rv : bestBranch.getRegisters()) {
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
                    retTypes.add(getDataTypeForStorage(program, s, rv));
                    retRegNames.add(regName);
                }
            }

            // Without CF in the return storage the decompiler assumes the flag
            // survives the call, so a following JC tests the caller's stale CF.
            VariableStorage cfStorage = getCarryFlagResultStorage(program, returns);
            if (cfStorage != null) {
                retStorages.add(cfStorage);
                retNames.add("CF");
                retTypes.add(BooleanDataType.dataType);
                retRegNames.add("CF");
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
     * Determine whether an input register is pinned to a constant (the
     * function selector, or a qualifier such as {@code BX = 4D41h}). Those
     * identify the entry rather than carry an argument.
     */
    private boolean isFunctionSelector(RegisterValue rv) {
        return "=".equals(rv.getOperator()) && EntrySelector.parseHexValue(rv.getValue()) != null;
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

    /**
     * Returns CF storage when the entry's outcome is reported through the
     * carry flag, or {@code null} when CF is not part of the result.
     */
    private VariableStorage getCarryFlagResultStorage(Program program,
                                                      List<ReturnBranch> returns) {
        for (ReturnBranch branch : returns) {
            String cond = branch.getCondition();
            if (cond != null && cond.trim().toUpperCase(Locale.ROOT).startsWith("CF ")) {
                return resolveFlagStorage(program, "CF");
            }
        }
        return null;
    }

    private VariableStorage resolveFlagStorage(Program program, String flagName) {
        Register flag = program.getRegister(flagName);
        if (flag == null) {
            return null;
        }
        try {
            return new VariableStorage(program, flag);
        } catch (InvalidInputException e) {
            return null;
        }
    }

    /**
     * Joins the storages into one multi-varnode storage. Varnodes run most
     * significant first, while the result struct's fields run from offset 0
     * on a little-endian target, so the fields are joined last to first to
     * keep each on its own registers. A field's own varnodes (e.g. DS then DX)
     * are already most significant first and keep their order.
     */
    private VariableStorage buildCompositeStorage(Program program,
                                                   List<VariableStorage> storages)
            throws Exception {
        List<Varnode> allVarnodes = new ArrayList<>();
        for (VariableStorage s : storages.reversed()) {
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

        // RBIL writes register pairs high part first (DS:DX, CX:DX), which
        // is also the order VariableStorage expects for joined varnodes.
        if (regName.contains(":")) {
            String[] parts = regName.split(":");
            if (parts.length == 2) {
                Register highReg = program.getRegister(parts[0].trim());
                Register lowReg = program.getRegister(parts[1].trim());
                if (highReg != null && lowReg != null) {
                    try {
                        return new VariableStorage(program, highReg, lowReg);
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

    /**
     * Picks a type whose size matches the storage exactly; a mismatch makes
     * Ghidra reject the parameter. Pointers are sized explicitly because an
     * unsized pointer resolves to the program's 2-byte near pointer, which
     * cannot occupy a SEG:OFF register pair.
     */
    private DataType getDataTypeForStorage(Program program, VariableStorage storage,
                                           RegisterValue rv) {
        int size = storage.size();
        if ("->".equals(rv.getOperator()) && (size == 2 || size == 4)) {
            return new PointerDataType(getPointeeType(rv), size, program.getDataTypeManager());
        }
        switch (size) {
            case 1: return ByteDataType.dataType;
            case 2: return WordDataType.dataType;
            case 4: return DWordDataType.dataType;
            default: return Undefined.getUndefinedDataType(size);
        }
    }

    private static DataType getPointeeType(RegisterValue rv) {
        String desc = rv.getDescription();
        if (desc != null) {
            String lower = desc.toLowerCase(Locale.ROOT);
            if (lower.contains("asciz") || lower.contains("string")) {
                return CharDataType.dataType;
            }
        }
        return VoidDataType.dataType;
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
        // x86 lifts INT n to "intloc = swi(n); call [intloc]". A primary
        // CALL_OVERRIDE_UNCONDITIONAL turns that CALLIND into a direct call to
        // the stub, so the decompiler applies the stub's register prototype.
        // CALLOTHER_OVERRIDE_CALL would instead rewrite swi() into a CALL that
        // keeps swi's output, leaving the CALLIND behind it intact.
        // A plain DATA reference only gives Listing navigation.
        RefType type = overrideCalls ? RefType.CALL_OVERRIDE_UNCONDITIONAL : RefType.DATA;
        ReferenceManager refManager = program.getReferenceManager();

        // Only one primary reference per operand is honored, so drop stale
        // references to the overlay left by a run with the other setting.
        for (Reference ref : refManager.getReferencesFrom(intAddr, Reference.MNEMONIC)) {
            if (ref.getToAddress().getAddressSpace().equals(overlaySpace)
                    && !ref.getReferenceType().equals(type)) {
                refManager.delete(ref);
            }
        }

        Reference ref = refManager.addMemoryReference(
                intAddr, overlayAddr, type, SourceType.ANALYSIS, Reference.MNEMONIC);
        refManager.setPrimary(ref, true);
    }
}
