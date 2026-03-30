package ghidradosinterruptresolver.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A single interrupt entry from Ralf Brown's Interrupt List,
 * representing one function or sub-function of an interrupt vector.
 */
public final class InterruptEntry {

    private final String entryType;
    private final String id;
    private final String category;
    private final String title;
    private final String source;
    private final String interrupt;
    private final String function;
    private final List<EntryFlag> flags;
    private final List<RegisterValue> inputRegisters;
    private final List<ReturnBranch> returns;
    private final String description;
    private final String program;
    private final List<String> notes;
    private final List<String> bugs;
    private final List<String> index;
    private final List<String> tables;
    private final List<String> tableRefs;

    private InterruptEntry(String entryType, String id, String category,
                           String title, String source, String interrupt,
                           String function, List<EntryFlag> flags,
                           List<RegisterValue> inputRegisters,
                           List<ReturnBranch> returns, String description,
                           String program, List<String> notes,
                           List<String> bugs, List<String> index,
                           List<String> tables, List<String> tableRefs) {
        this.entryType = entryType;
        this.id = id;
        this.category = category;
        this.title = title;
        this.source = source;
        this.interrupt = interrupt;
        this.function = function;
        this.flags = flags;
        this.inputRegisters = inputRegisters;
        this.returns = returns;
        this.description = description;
        this.program = program;
        this.notes = notes;
        this.bugs = bugs;
        this.index = index;
        this.tables = tables;
        this.tableRefs = tableRefs;
    }

    @SuppressWarnings("unchecked")
    public static InterruptEntry fromMap(Map<String, Object> map) {
        if (map == null) {
            return new InterruptEntry(null, null, null, null, null, null,
                    null, Collections.emptyList(), Collections.emptyList(),
                    Collections.emptyList(), null, null,
                    Collections.emptyList(), Collections.emptyList(),
                    Collections.emptyList(), Collections.emptyList(),
                    Collections.emptyList());
        }

        // Use toString() for all fields — SnakeYAML's YAML 1.1 SafeConstructor
        // parses bare Y/y/N/n as Boolean, which would ClassCastException on (String) cast.
        Object rawEntryType = map.get("entry_type");
        String entryType = rawEntryType != null ? rawEntryType.toString() : null;

        Object rawId = map.get("id");
        String id = rawId != null ? rawId.toString() : null;

        Object rawCategory = map.get("category");
        String category = rawCategory != null ? rawCategory.toString() : null;

        Object rawTitle = map.get("title");
        String title = rawTitle != null ? rawTitle.toString() : null;

        Object rawSource = map.get("source");
        String source = rawSource != null ? rawSource.toString() : null;

        Object rawInterrupt = map.get("interrupt");
        String interrupt = rawInterrupt != null ? rawInterrupt.toString() : null;

        Object rawFunction = map.get("function");
        String function;
        if (rawFunction == null) {
            function = null;
        } else if (rawFunction instanceof Number) {
            // SnakeYAML may parse unquoted values like 07 as octal Integer (7).
            // Re-format as zero-padded uppercase hex to match the lookup key format.
            int numValue = ((Number) rawFunction).intValue();
            function = numValue <= 0xFF
                    ? String.format("%02X", numValue)
                    : String.format("%04X", numValue);
        } else {
            function = rawFunction.toString();
        }

        Object rawDescription = map.get("description");
        String description = rawDescription != null ? rawDescription.toString() : null;

        Object rawProgram = map.get("program");
        String program = rawProgram != null ? rawProgram.toString() : null;

        // --- flags ---
        List<EntryFlag> flags;
        List<Object> rawFlags =
                (List<Object>) map.getOrDefault("flags", Collections.emptyList());
        if (rawFlags == null || rawFlags.isEmpty()) {
            flags = Collections.emptyList();
        } else {
            flags = new ArrayList<>(rawFlags.size());
            for (Object code : rawFlags) {
                EntryFlag flag = EntryFlag.fromCode(
                        code != null ? code.toString() : null);
                if (flag != null) {
                    flags.add(flag);
                }
            }
            flags = Collections.unmodifiableList(flags);
        }

        // --- input_registers ---
        List<RegisterValue> inputRegisters;
        List<Map<String, Object>> rawInputRegs =
                (List<Map<String, Object>>) map.getOrDefault("input_registers",
                        Collections.emptyList());
        if (rawInputRegs == null || rawInputRegs.isEmpty()) {
            inputRegisters = Collections.emptyList();
        } else {
            inputRegisters = new ArrayList<>(rawInputRegs.size());
            for (Map<String, Object> raw : rawInputRegs) {
                inputRegisters.add(RegisterValue.fromMap(raw));
            }
            inputRegisters = Collections.unmodifiableList(inputRegisters);
        }

        // --- returns ---
        List<ReturnBranch> returns;
        List<Map<String, Object>> rawReturns =
                (List<Map<String, Object>>) map.getOrDefault("returns",
                        Collections.emptyList());
        if (rawReturns == null || rawReturns.isEmpty()) {
            returns = Collections.emptyList();
        } else {
            returns = new ArrayList<>(rawReturns.size());
            for (Map<String, Object> raw : rawReturns) {
                returns.add(ReturnBranch.fromMap(raw));
            }
            returns = Collections.unmodifiableList(returns);
        }

        // --- string lists ---
        List<String> notes = toStringList(
                (List<Object>) map.getOrDefault("notes", Collections.emptyList()));
        List<String> bugs = toStringList(
                (List<Object>) map.getOrDefault("bugs", Collections.emptyList()));
        List<String> index = toStringList(
                (List<Object>) map.getOrDefault("index", Collections.emptyList()));
        List<String> tables = toStringList(
                (List<Object>) map.getOrDefault("tables", Collections.emptyList()));
        List<String> tableRefs = toStringList(
                (List<Object>) map.getOrDefault("table_refs", Collections.emptyList()));

        return new InterruptEntry(entryType, id, category, title, source,
                interrupt, function, flags, inputRegisters, returns,
                description, program, notes, bugs, index, tables, tableRefs);
    }

    /**
     * Convert a raw list of objects to an unmodifiable list of strings.
     */
    private static List<String> toStringList(List<Object> raw) {
        if (raw == null || raw.isEmpty()) {
            return Collections.emptyList();
        }
        List<String> result = new ArrayList<>(raw.size());
        for (Object item : raw) {
            result.add(item != null ? item.toString() : null);
        }
        return Collections.unmodifiableList(result);
    }

    public String getEntryType() {
        return entryType;
    }

    public String getId() {
        return id;
    }

    public String getCategory() {
        return category;
    }

    public String getTitle() {
        return title;
    }

    public String getSource() {
        return source;
    }

    public String getInterrupt() {
        return interrupt;
    }

    public String getFunction() {
        return function;
    }

    public List<EntryFlag> getFlags() {
        return flags;
    }

    public List<RegisterValue> getInputRegisters() {
        return inputRegisters;
    }

    public List<ReturnBranch> getReturns() {
        return returns;
    }

    public String getDescription() {
        return description;
    }

    public String getProgram() {
        return program;
    }

    public List<String> getNotes() {
        return notes;
    }

    public List<String> getBugs() {
        return bugs;
    }

    public List<String> getIndex() {
        return index;
    }

    public List<String> getTables() {
        return tables;
    }

    public List<String> getTableRefs() {
        return tableRefs;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("InterruptEntry{");
        sb.append("id='").append(id).append('\'');
        sb.append(", interrupt='").append(interrupt).append('\'');
        if (function != null) {
            sb.append(", function='").append(function).append('\'');
        }
        sb.append(", title='").append(title).append('\'');
        if (!flags.isEmpty()) {
            sb.append(", flags=").append(flags);
        }
        sb.append('}');
        return sb.toString();
    }
}
