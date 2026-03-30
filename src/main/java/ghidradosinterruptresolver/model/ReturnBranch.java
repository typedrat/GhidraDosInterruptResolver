package ghidradosinterruptresolver.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * One branch of an interrupt entry's return specification.
 * A single entry may have multiple return branches distinguished
 * by condition (e.g. "CF clear" vs "CF set").
 */
public final class ReturnBranch {

    private final String condition;
    private final String conditionDescription;
    private final List<RegisterValue> registers;
    private final List<String> rawLines;

    private ReturnBranch(String condition, String conditionDescription,
                         List<RegisterValue> registers, List<String> rawLines) {
        this.condition = condition;
        this.conditionDescription = conditionDescription;
        this.registers = registers;
        this.rawLines = rawLines;
    }

    @SuppressWarnings("unchecked")
    public static ReturnBranch fromMap(Map<String, Object> map) {
        if (map == null) {
            return new ReturnBranch(null, null,
                    Collections.emptyList(), Collections.emptyList());
        }

        Object rawCondition = map.get("condition");
        String condition = rawCondition != null ? rawCondition.toString() : null;

        Object rawCondDesc = map.get("condition_description");
        String conditionDescription = rawCondDesc != null ? rawCondDesc.toString() : null;

        List<RegisterValue> registers;
        List<Map<String, Object>> rawRegisters =
                (List<Map<String, Object>>) map.getOrDefault("registers", Collections.emptyList());
        if (rawRegisters == null || rawRegisters.isEmpty()) {
            registers = Collections.emptyList();
        } else {
            registers = new ArrayList<>(rawRegisters.size());
            for (Map<String, Object> raw : rawRegisters) {
                registers.add(RegisterValue.fromMap(raw));
            }
            registers = Collections.unmodifiableList(registers);
        }

        List<String> rawLines;
        List<Object> rawRawLines =
                (List<Object>) map.getOrDefault("raw_lines", Collections.emptyList());
        if (rawRawLines == null || rawRawLines.isEmpty()) {
            rawLines = Collections.emptyList();
        } else {
            rawLines = new ArrayList<>(rawRawLines.size());
            for (Object line : rawRawLines) {
                rawLines.add(line != null ? line.toString() : null);
            }
            rawLines = Collections.unmodifiableList(rawLines);
        }

        return new ReturnBranch(condition, conditionDescription, registers, rawLines);
    }

    public String getCondition() {
        return condition;
    }

    public String getConditionDescription() {
        return conditionDescription;
    }

    public List<RegisterValue> getRegisters() {
        return registers;
    }

    public List<String> getRawLines() {
        return rawLines;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("ReturnBranch{");
        if (condition != null) {
            sb.append("condition='").append(condition).append('\'');
        }
        if (conditionDescription != null) {
            sb.append(", conditionDescription='").append(conditionDescription).append('\'');
        }
        if (!registers.isEmpty()) {
            sb.append(", registers=").append(registers);
        }
        if (!rawLines.isEmpty()) {
            sb.append(", rawLines=").append(rawLines);
        }
        sb.append('}');
        return sb.toString();
    }
}
