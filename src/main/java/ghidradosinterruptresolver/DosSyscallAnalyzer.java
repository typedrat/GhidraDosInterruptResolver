package ghidradosinterruptresolver;

import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Set;

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

/**
 * Ghidra analyzer that identifies and annotates x86 DOS/BIOS interrupt calls
 * ({@code INT nn}) using definitions from Ralf Brown's Interrupt List.
 *
 * <p>For each {@code INT} instruction in the analyzed address set, this analyzer:
 * <ol>
 *   <li>Extracts the interrupt vector number from the instruction operand</li>
 *   <li>Resolves the AH and AL register values (function/sub-function selectors)
 *       using backward analysis</li>
 *   <li>Looks up the interrupt definition in the YAML database, using any
 *       other registers the candidates pin to tell apart entries that
 *       share a selector</li>
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
    private static final String OPT_CALL_OVERRIDE = "Override INT as call to overlay function";
    private static final String OPT_HIDE_SWI = "Hide swi() on overridden INT calls";
    private static final String OPT_TRUSTED_CATEGORIES = "Trusted RBIL categories";

    /** DOS, BIOS, video, mouse, memory managers, serial, Windows, CPU. */
    private static final String DEFAULT_TRUSTED_CATEGORIES = "DBVMmSWC";

    private boolean addPlateComments = true;
    private boolean addPrePostComments = true;
    private boolean createOverlayFunctions = true;
    private boolean addBookmarks = true;
    private boolean addReferences = true;
    private boolean overrideCalls = true;
    private boolean hideSwi = true;
    private String trustedCategories = DEFAULT_TRUSTED_CATEGORIES;

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
        options.registerOption(OPT_CALL_OVERRIDE, true, null,
                "Make the reference a call override so the decompiler shows a typed call " +
                "to the overlay function instead of an indirect call through the vector");
        options.registerOption(OPT_HIDE_SWI, true, null,
                "Install a program spec extension (callotherfixup) that defines swi() as " +
                "the vector table offset, so the decompiler drops the leftover swi(n) " +
                "statement in front of each overridden call. Requires call overrides.");
        options.registerOption(OPT_TRUSTED_CATEGORIES, DEFAULT_TRUSTED_CATEGORIES, null,
                "RBIL category letters (case-sensitive) whose standard service, the first " +
                "entry listed for a selector, is assumed from AH/AX alone. Other entries " +
                "need a confirmed qualifier register such as BX or DX; calls with no such " +
                "match are left as INTxxh_..._UNKNOWN with the candidates in a comment.");
    }

    @Override
    public void optionsChanged(Options options, Program program) {
        addPlateComments = options.getBoolean(OPT_PLATE_COMMENTS, true);
        addPrePostComments = options.getBoolean(OPT_PRE_POST_COMMENTS, true);
        createOverlayFunctions = options.getBoolean(OPT_OVERLAY_FUNCTIONS, true);
        addBookmarks = options.getBoolean(OPT_BOOKMARKS, true);
        addReferences = options.getBoolean(OPT_REFERENCES, true);
        overrideCalls = options.getBoolean(OPT_CALL_OVERRIDE, true);
        hideSwi = options.getBoolean(OPT_HIDE_SWI, true);
        trustedCategories = options.getString(OPT_TRUSTED_CATEGORIES,
                DEFAULT_TRUSTED_CATEGORIES);
    }

    @Override
    public boolean added(Program program, AddressSetView set, TaskMonitor monitor,
                         MessageLog log) throws CancelledException {

        InterruptDatabase db = InterruptDatabase.getInstance();
        RegisterResolver resolver = new RegisterResolver();
        EntrySelector selector = new EntrySelector(resolver, parseCategories(trustedCategories));
        SyscallAnnotator annotator = new SyscallAnnotator(
                addPlateComments, addPrePostComments, createOverlayFunctions,
                addBookmarks, addReferences, overrideCalls);

        // Initialize overlay space if needed (for overlay functions or references)
        boolean haveOverlay = false;
        if (createOverlayFunctions || addReferences) {
            haveOverlay = annotator.initOverlaySpace(program);
            if (!haveOverlay) {
                log.appendMsg(ANALYZER_NAME,
                        "Failed to create overlay address space. " +
                        "Overlay functions and references will be skipped.");
                // Continue -- comments and bookmarks still work
            }
        }

        // The fixup is only safe when every INT gets a call override;
        // otherwise the decompiler would show calls through vector-table
        // addresses.
        if (hideSwi && overrideCalls && createOverlayFunctions && addReferences
                && haveOverlay) {
            SwiFixup.install(program, monitor);
        } else {
            SwiFixup.remove(program, monitor);
        }

        monitor.initialize(set.getNumAddresses());
        monitor.setMessage("Resolving INT instructions...");
        int count = 0;

        InstructionIterator it = program.getListing().getInstructions(set, true);
        while (it.hasNext()) {
            monitor.checkCancelled();
            Instruction insn = it.next();
            monitor.incrementProgress(insn.getLength());

            int interruptNumber = getInterruptNumber(insn);
            if (interruptNumber < 0) {
                continue;
            }

            Long ahValue = resolver.resolveAH(program, insn.getAddress(), monitor);
            Long alValue = resolver.resolveAL(program, insn.getAddress(), monitor);

            List<InterruptDatabase.Level> levels =
                    db.lookupLevels(interruptNumber, ahValue, alValue);
            EntrySelector.Selection selection =
                    selector.select(program, insn.getAddress(), levels, monitor);
            if (selection.entry() == null) {
                annotator.annotateUnresolved(program, insn.getAddress(), interruptNumber,
                        ahValue, alValue, selection.candidates());
                continue;
            }

            annotator.annotate(program, insn.getAddress(), interruptNumber, selection.entry());
            count++;
        }

        monitor.setProgress(set.getNumAddresses());

        if (count > 0) {
            log.appendMsg(ANALYZER_NAME,
                    "Resolved " + count + " interrupt call(s).");
        }

        return true;
    }

    private static Set<String> parseCategories(String letters) {
        Set<String> categories = new HashSet<>();
        if (letters != null) {
            letters.codePoints()
                    .filter(Character::isLetter)
                    .forEach(c -> categories.add(Character.toString(c)));
        }
        return categories;
    }

    /**
     * Extract the interrupt vector number from an INT-family instruction:
     * the operand of {@code INT n}, or the fixed vector of {@code INT1},
     * {@code INT3} and {@code INTO}, which also lift to swi().
     *
     * @param insn the instruction
     * @return the interrupt number (0-255), or -1 if it is not an INT
     */
    private int getInterruptNumber(Instruction insn) {
        String mnemonic = insn.getMnemonicString().toUpperCase(Locale.ROOT);
        switch (mnemonic) {
            case "INT1": return 0x01;
            case "INT3": return 0x03;
            case "INTO": return 0x04;
            case "INT": break;
            default: return -1;
        }
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
