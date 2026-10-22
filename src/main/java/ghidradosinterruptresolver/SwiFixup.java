package ghidradosinterruptresolver;

import ghidra.program.database.SpecExtension;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;

/**
 * Manages a program-level compiler spec extension that replaces the x86
 * {@code swi} pcodeop with plain arithmetic.
 *
 * <p>x86 lifts {@code INT n} to {@code intloc = swi(n); call [intloc]}. Once
 * a call override turns the {@code call} into a direct call to a stub,
 * {@code swi}'s result is unused, but the decompiler still prints the
 * pcodeop as a statement because it cannot assume user-defined ops are free
 * of side effects. Defining {@code swi(n)} as the real-mode vector table
 * offset {@code n * 4} makes it ordinary dead code that the decompiler drops.
 */
public final class SwiFixup {

    private static final String TARGET_OP = "swi";

    private static final String FIXUP_XML = """
            <callotherfixup targetop="swi">
              <pcode>
                <input name="vector"/>
                <output name="dest"/>
                <body><![CDATA[
                  dest = zext(vector) * 4;
                ]]></body>
              </pcode>
            </callotherfixup>
            """;

    private SwiFixup() {
    }

    /**
     * Installs the fixup if absent. A different {@code swi} fixup the user
     * installed is left untouched.
     *
     * @return {@code true} if the fixup is in place afterwards
     */
    public static boolean install(Program program, TaskMonitor monitor) {
        String current = getInstalled(program);
        if (current != null) {
            return current.equals(FIXUP_XML);
        }
        try {
            new SpecExtension(program).addReplaceCompilerSpecExtension(FIXUP_XML, monitor);
            return true;
        } catch (Exception e) {
            Msg.warn(SwiFixup.class, "Failed to install swi() fixup: " + e.getMessage());
            return false;
        }
    }

    /** Removes the fixup if this extension installed it. */
    public static void remove(Program program, TaskMonitor monitor) {
        if (!FIXUP_XML.equals(getInstalled(program))) {
            return;
        }
        try {
            new SpecExtension(program).removeCompilerSpecExtension(
                    SpecExtension.Type.CALLOTHER_FIXUP.getOptionName(TARGET_OP), monitor);
        } catch (Exception e) {
            Msg.warn(SwiFixup.class, "Failed to remove swi() fixup: " + e.getMessage());
        }
    }

    private static String getInstalled(Program program) {
        return SpecExtension.getCompilerSpecExtension(
                program, SpecExtension.Type.CALLOTHER_FIXUP, TARGET_OP);
    }
}
