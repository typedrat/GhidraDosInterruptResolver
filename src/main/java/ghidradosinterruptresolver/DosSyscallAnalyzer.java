package ghidradosinterruptresolver;

import java.util.List;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidradosinterruptresolver.model.InterruptEntry;

/**
 * Ghidra analyzer that identifies and annotates x86 DOS/BIOS interrupt calls
 * ({@code INT nn}) using definitions from Ralf Brown's Interrupt List.
 *
 * <p>For each {@code INT} instruction in the analyzed address set, this analyzer:
 * <ol>
 *   <li>Extracts the interrupt vector number from the instruction operand</li>
 *   <li>Resolves the AH and AL register values (function/sub-function selectors)
 *       using backward analysis</li>
 *   <li>Looks up the interrupt definition in the YAML database</li>
 *   <li>Annotates the instruction with comments, bookmarks, overlay functions,
 *       and/or references as configured by the user</li>
 * </ol>
 *
 * <p>This analyzer only activates for x86 16-bit Real Mode programs.
 */
public class DosSyscallAnalyzer extends AbstractAnalyzer {

    private static final String ANALYZER_NAME = "DOS Interrupt Resolver";
    private static final String ANALYZER_DESCRIPTION =
            "Resolves x86 DOS/BIOS interrupt calls using Ralf Brown's Interrupt List";

    private static final String OPT_PLATE_COMMENTS = "Add plate comments";
    private static final String OPT_PRE_POST_COMMENTS = "Add pre/post comments";
    private static final String OPT_OVERLAY_FUNCTIONS = "Create overlay functions";
    private static final String OPT_BOOKMARKS = "Add bookmarks";
    private static final String OPT_REFERENCES = "Add references";

    private boolean addPlateComments = true;
    private boolean addPrePostComments = true;
    private boolean createOverlayFunctions = true;
    private boolean addBookmarks = true;
    private boolean addReferences = true;

    public DosSyscallAnalyzer() {
        super(ANALYZER_NAME, ANALYZER_DESCRIPTION, AnalyzerType.INSTRUCTION_ANALYZER);
        setPriority(AnalysisPriority.DATA_TYPE_PROPOGATION.after());
        setDefaultEnablement(true);
        setSupportsOneTimeAnalysis();
    }

    @Override
    public boolean canAnalyze(Program program) {
        return program.getLanguage().getLanguageID().getIdAsString()
                .contains("x86:LE:16:Real Mode");
    }

    @Override
    public void registerOptions(Options options, Program program) {
        options.registerOption(OPT_PLATE_COMMENTS, true, null,
                "Add function title as plate comment on INT instructions");
        options.registerOption(OPT_PRE_POST_COMMENTS, true, null,
                "Add input register and return value comments");
        options.registerOption(OPT_OVERLAY_FUNCTIONS, true, null,
                "Create named functions in INT overlay space");
        options.registerOption(OPT_BOOKMARKS, true, null,
                "Add analysis bookmarks on INT instructions");
        options.registerOption(OPT_REFERENCES, true, null,
                "Add navigable references from INT instructions to overlay functions");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        addPlateComments = options.getBoolean(OPT_PLATE_COMMENTS, true);
        addPrePostComments = options.getBoolean(OPT_PRE_POST_COMMENTS, true);
        createOverlayFunctions = options.getBoolean(OPT_OVERLAY_FUNCTIONS, true);
        addBookmarks = options.getBoolean(OPT_BOOKMARKS, true);
        addReferences = options.getBoolean(OPT_REFERENCES, true);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
                         MessageLog log) throws CancelledException {

        InterruptDatabase db = InterruptDatabase.getInstance();
        RegisterResolver resolver = new RegisterResolver();
        SyscallAnnotator annotator = new SyscallAnnotator(
                addPlateComments, addPrePostComments, createOverlayFunctions,
                addBookmarks, addReferences);

        // Initialize overlay space if needed (for overlay functions or references)
        if (createOverlayFunctions || addReferences) {
            if (!annotator.initOverlaySpace(program)) {
                log.appendMsg(ANALYZER_NAME,
                        "Failed to create overlay address space. " +
                        "Overlay functions and references will be skipped.");
                // Continue -- comments and bookmarks still work
            }
        }

        monitor.initialize(set.getNumAddresses());
        monitor.setMessage("Resolving INT instructions...");
        int count = 0;

        InstructionIterator it = program.getListing().getInstructions(set, true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction insn = it.next();
            monitor.incrementProgress(insn.getLength());

            if (!"INT".equalsIgnoreCase(insn.getMnemonicString())) {
                continue;
            }

            int interruptNumber = getInterruptNumber(insn);
            if (interruptNumber < 0) {
                continue;
            }

            Long ahValue = resolver.resolveAH(program, insn.getAddress(), monitor);
            Long alValue = resolver.resolveAL(program, insn.getAddress(), monitor);

            List<InterruptEntry> entries = db.lookup(interruptNumber, ahValue, alValue);
            if (entries.isEmpty()) {
                continue;
            }

            // Use the first (best) match
            InterruptEntry entry = entries.get(0);

            annotator.annotate(program, insn.getAddress(), interruptNumber, entry);
            count++;
        }

        monitor.setProgress(set.getNumAddresses());

        if (count > 0) {
            log.appendMsg(ANALYZER_NAME,
                    "Resolved " + count + " interrupt call(s).");
        }

        return true;
    }

    /**
     * Extract the interrupt vector number from an INT instruction's operand.
     *
     * @param insn the INT instruction
     * @return the interrupt number (0-255), or -1 if it could not be extracted
     */
    private int getInterruptNumber(Instruction insn) {
        Object[] opObjects = insn.getOpObjects(0);
        if (opObjects != null) {
            for (Object obj : opObjects) {
                if (obj instanceof Scalar) {
                    long val = ((Scalar) obj).getUnsignedValue();
                    if (val > 0xFF) {
                        return -1;
                    }
                    return (int) val;
                }
            }
        }
        return -1;
    }
}
