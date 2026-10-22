package ghidradosinterruptresolver;

import java.util.HashMap;
import java.util.Map;

import ghidra.app.plugin.core.analysis.ConstantPropagationContextEvaluator;
import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceIterator;
import ghidra.program.util.SymbolicPropogator;
import ghidra.util.Msg;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * Resolves register values at INT instruction addresses using two strategies:
 * symbolic propagation (via Ghidra's constant propagation engine) and a
 * backward instruction scan.
 *
 * <p>In DOS x86 16-bit Real Mode programs, interrupt calls set up registers
 * (typically AH for the function number) before executing {@code INT nn}.
 * This class determines those register values so the caller can look up the
 * specific interrupt function being invoked.
 */
public class RegisterResolver {

    /** Maximum number of instructions to walk backwards during a scan. */
    private static final int MAX_BACKWARD_SCAN = 30;

    /**
     * Cache of SymbolicPropogator instances keyed by function entry point.
     * flowConstants is expensive, so we avoid re-running it when resolving
     * multiple registers (e.g. AH and AL) within the same function.
     */
    private final Map<Address, SymbolicPropogator> symCache = new HashMap<>();

    /**
     * Try to resolve a register value at the given INT instruction address.
     * Uses symbolic propagation first (if the instruction is inside a
     * recognized function), then falls back to a backward instruction scan.
     *
     * @param program  the current program
     * @param intAddr  the address of the INT instruction
     * @param register the register whose value is desired (e.g. AH, AL)
     * @param monitor  task monitor for cancellation support
     * @return the resolved value, or {@code null} if it cannot be determined
     */
    public Long resolveRegister(Program program, Address intAddr,
                                Register register, TaskMonitor monitor) {
        Long value = resolveSymbolic(program, intAddr, register, monitor);
        if (value != null) {
            return value;
        }
        return resolveBackward(program, intAddr, register);
    }

    /**
     * Convenience method to resolve the AH register value at an INT instruction.
     *
     * @param program the current program
     * @param intAddr the address of the INT instruction
     * @param monitor task monitor for cancellation support
     * @return the AH value, or {@code null} if it cannot be determined
     */
    public Long resolveAH(Program program, Address intAddr, TaskMonitor monitor) {
        Register ah = program.getLanguage().getRegister("AH");
        if (ah == null) {
            Msg.warn(this, "AH register not found in program language");
            return null;
        }
        return resolveRegister(program, intAddr, ah, monitor);
    }

    /**
     * Convenience method to resolve the AL register value at an INT instruction.
     *
     * @param program the current program
     * @param intAddr the address of the INT instruction
     * @param monitor task monitor for cancellation support
     * @return the AL value, or {@code null} if it cannot be determined
     */
    public Long resolveAL(Program program, Address intAddr, TaskMonitor monitor) {
        Register al = program.getLanguage().getRegister("AL");
        if (al == null) {
            Msg.warn(this, "AL register not found in program language");
            return null;
        }
        return resolveRegister(program, intAddr, al, monitor);
    }

    // -----------------------------------------------------------------------
    // Strategy 1: Symbolic Propagation
    // -----------------------------------------------------------------------

    /**
     * Attempt to resolve the register value using Ghidra's constant
     * propagation engine. This only works when the INT instruction lives
     * inside a recognized function.
     */
    private Long resolveSymbolic(Program program, Address intAddr,
                                 Register register, TaskMonitor monitor) {
        Function func = program.getFunctionManager().getFunctionContaining(intAddr);
        if (func == null) {
            return null;
        }

        try {
            Address entryPoint = func.getEntryPoint();
            SymbolicPropogator symEval = symCache.get(entryPoint);
            if (symEval == null) {
                symEval = new SymbolicPropogator(program);
                symEval.flowConstants(
                    entryPoint,
                    func.getBody(),
                    new ConstantPropagationContextEvaluator(monitor, true),
                    true,
                    monitor
                );
                symCache.put(entryPoint, symEval);
            }

            // Try the exact register first.
            SymbolicPropogator.Value val = symEval.getRegisterValue(intAddr, register);
            if (val != null) {
                return maskForRegister(val.getValue(), register);
            }

            // A sub-register (e.g. AH, BL) may only be known through its parent.
            for (Register parent = register.getParentRegister(); parent != null;
                    parent = parent.getParentRegister()) {
                SymbolicPropogator.Value parentVal = symEval.getRegisterValue(intAddr, parent);
                if (parentVal != null) {
                    return extractSubRegister(parentVal.getValue(), parent, register);
                }
            }
        } catch (CancelledException e) {
            Msg.warn(this, "Symbolic propagation cancelled at " + intAddr);
        }

        return null;
    }

    // -----------------------------------------------------------------------
    // Strategy 2: Backward Instruction Scan
    // -----------------------------------------------------------------------

    /**
     * Walk backwards from the INT instruction looking for an instruction
     * that sets the target register to an immediate value.
     */
    private Long resolveBackward(Program program, Address intAddr, Register register) {
        Address currentAddr = intAddr;
        for (int i = 0; i < MAX_BACKWARD_SCAN; i++) {
            Instruction insn = program.getListing().getInstructionBefore(currentAddr);
            if (insn == null) {
                break;
            }

            // Check for basic block boundaries before inspecting this instruction.
            if (isBlockBoundary(program, insn, intAddr)) {
                break;
            }

            String mnemonic = insn.getMnemonicString().toUpperCase();

            // MOV reg, imm
            if (mnemonic.equals("MOV")) {
                Long result = checkMovInstruction(insn, register);
                if (result != null) {
                    return result;
                }
            }

            // XOR reg, reg  ->  value is 0
            if (mnemonic.equals("XOR") || mnemonic.equals("SUB")) {
                Long result = checkZeroIdiom(insn, register);
                if (result != null) {
                    return result;
                }
            }

            // If this instruction writes to the target register but wasn't
            // recognized above, the value is unknown — stop scanning.
            if (writesToRegister(insn, register)) {
                break;
            }

            currentAddr = insn.getAddress();
        }

        return null;
    }

    /**
     * Check if a MOV instruction sets the target register, or a register
     * containing it (e.g. {@code MOV BX, imm} for BL), to an immediate value.
     */
    private Long checkMovInstruction(Instruction insn, Register target) {
        Register destReg = getRegisterOperand(insn, 0);
        if (destReg == null) {
            return null;
        }

        Scalar imm = getScalarOperand(insn, 1);
        if (imm == null) {
            return null;
        }

        long immValue = imm.getUnsignedValue();

        if (destReg.equals(target)) {
            return maskForRegister(immValue, target);
        }
        if (destReg.contains(target)) {
            return extractSubRegister(immValue, destReg, target);
        }

        return null;
    }

    /**
     * Check if an XOR or SUB instruction zeros the target register or a
     * register containing it (e.g. {@code XOR AX, AX} for AH).
     */
    private Long checkZeroIdiom(Instruction insn, Register target) {
        Register op0 = getRegisterOperand(insn, 0);
        Register op1 = getRegisterOperand(insn, 1);
        if (op0 == null || op1 == null) {
            return null;
        }

        if (op0.equals(op1) && (op0.equals(target) || op0.contains(target))) {
            return 0L;
        }

        return null;
    }

    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /**
     * Check whether an instruction writes to any register overlapping the
     * target, indicating the register value is clobbered.
     */
    private boolean writesToRegister(Instruction insn, Register target) {
        Object[] results = insn.getResultObjects();
        if (results == null) {
            return false;
        }
        for (Object obj : results) {
            if (obj instanceof Register written
                    && (written.contains(target) || target.contains(written))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determine whether the given instruction marks a basic-block boundary
     * that should stop the backward scan.
     */
    private boolean isBlockBoundary(Program program, Instruction insn, Address intAddr) {
        String mnemonic = insn.getMnemonicString().toUpperCase();

        // HLT stops the processor; treat as a block boundary.
        if (mnemonic.equals("HLT")) {
            return true;
        }

        // Unconditional jumps, calls, returns, and other INTs end the block.
        if (mnemonic.equals("JMP") || mnemonic.equals("JMPF")) {
            return true;
        }
        if (mnemonic.equals("CALL") || mnemonic.equals("CALLF")) {
            return true;
        }
        if (mnemonic.startsWith("RET") || mnemonic.startsWith("IRET")) {
            return true;
        }
        if (mnemonic.equals("INT") && !insn.getAddress().equals(intAddr)) {
            return true;
        }

        // If this instruction's address is a jump/call target from elsewhere
        // it starts a new basic block.
        Address addr = insn.getAddress();
        Function func = program.getFunctionManager().getFunctionAt(addr);
        if (func != null && !addr.equals(intAddr)) {
            return true;
        }

        ReferenceIterator refs = program.getReferenceManager().getReferencesTo(addr);
        while (refs.hasNext()) {
            Reference ref = refs.next();
            RefType refType = ref.getReferenceType();
            if (refType.isJump() || refType.isCall()) {
                return true;
            }
        }

        return false;
    }

    /**
     * Extract a register operand from the given operand index, or
     * {@code null} if the operand is not a simple register.
     */
    private Register getRegisterOperand(Instruction insn, int operandIndex) {
        // A memory operand such as [BX + 2] also lists BX among its objects.
        int type = insn.getOperandType(operandIndex);
        if (!OperandType.isRegister(type) || OperandType.isDynamic(type)) {
            return null;
        }
        Object[] opObjects = insn.getOpObjects(operandIndex);
        if (opObjects == null) {
            return null;
        }
        for (Object obj : opObjects) {
            if (obj instanceof Register) {
                return (Register) obj;
            }
        }
        return null;
    }

    /**
     * Extract a scalar (immediate) operand from the given operand index, or
     * {@code null} if the operand is not an immediate.
     */
    private Scalar getScalarOperand(Instruction insn, int operandIndex) {
        // A memory operand such as [BP + 4] also lists its displacement as a
        // Scalar, which is not the value being loaded.
        int type = insn.getOperandType(operandIndex);
        if (!OperandType.isScalar(type) || OperandType.isDynamic(type)
                || OperandType.isAddress(type)) {
            return null;
        }
        Object[] opObjects = insn.getOpObjects(operandIndex);
        if (opObjects == null) {
            return null;
        }
        for (Object obj : opObjects) {
            if (obj instanceof Scalar) {
                return (Scalar) obj;
            }
        }
        return null;
    }

    /**
     * Mask a resolved value to the appropriate width for the target register.
     * For 8-bit registers (AH, AL) this returns only the low byte.
     *
     * <p>When Ghidra's {@link SymbolicPropogator#getRegisterValue} is queried
     * for a sub-register (AH or AL), it returns the already-extracted value
     * for that sub-register, so a simple width mask is all that is needed here
     * -- no additional shifting is required.
     */
    private Long maskForRegister(long value, Register register) {
        int bitLength = register.getBitLength();
        if (bitLength <= 8) {
            return value & 0xFF;
        }
        if (bitLength <= 16) {
            return value & 0xFFFF;
        }
        return value;
    }

    /**
     * Given the value of {@code parent}, extract the bits belonging to
     * {@code target}, which it contains (e.g. AH from AX, BL from BX).
     */
    private Long extractSubRegister(long parentValue, Register parent, Register target) {
        int shift = target.getLeastSignificantBitInBaseRegister()
                - parent.getLeastSignificantBitInBaseRegister();
        return maskForRegister(parentValue >>> shift, target);
    }
}
