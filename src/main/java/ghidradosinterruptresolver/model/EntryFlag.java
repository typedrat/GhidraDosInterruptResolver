package ghidradosinterruptresolver.model;

/**
 * Flags that describe properties of an interrupt entry from
 * Ralf Brown's Interrupt List.
 */
public enum EntryFlag {

    UNDOCUMENTED("U"),
    PARTIALLY_DOCUMENTED("u"),
    PROTECTED_MODE("P"),
    REAL_MODE("R"),
    CALLBACK("C"),
    OBSOLETE("O");

    private final String code;

    EntryFlag(String code) {
        this.code = code;
    }

    public String getCode() {
        return code;
    }

    /**
     * Look up an EntryFlag by its single-character code.
     *
     * @param code the flag code from the YAML (e.g. "U", "P")
     * @return the matching EntryFlag, or null if unrecognised
     */
    public static EntryFlag fromCode(String code) {
        if (code == null) {
            return null;
        }
        for (EntryFlag flag : values()) {
            if (flag.code.equals(code)) {
                return flag;
            }
        }
        return null;
    }

    @Override
    public String toString() {
        return name() + "(" + code + ")";
    }
}
