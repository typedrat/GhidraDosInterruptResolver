package ghidradosinterruptresolver.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A register and its expected value or meaning within an interrupt
 * entry's input or return specification.
 */
public final class RegisterValue {

    private final String reg;
    private final String operator;
    private final String value;
    private final String description;
    private final List<String> tableRefs;
    private final List<SubValue> subValues;

    private RegisterValue(String reg, String operator, String value,
                          String description, List<String> tableRefs,
                          List<SubValue> subValues) {
        this.reg = reg;
        this.operator = operator;
        this.value = value;
        this.description = description;
        this.tableRefs = tableRefs;
        this.subValues = subValues;
    }

    @SuppressWarnings("unchecked")
    public static RegisterValue fromMap(Map<String, Object> map) {
        if (map == null) {
            return new RegisterValue(null, null, null, null,
                    Collections.emptyList(), Collections.emptyList());
        }

        // Use toString() to safely handle SnakeYAML parsing values as non-String types
        Object rawReg = map.get("reg");
        String reg = rawReg != null ? rawReg.toString() : null;

        Object rawOperator = map.get("operator");
        String operator = rawOperator != null ? rawOperator.toString() : null;

        Object rawValue = map.get("value");
        String value = rawValue != null ? rawValue.toString() : null;

        Object rawDescription = map.get("description");
        String description = rawDescription != null ? rawDescription.toString() : null;

        List<String> tableRefs;
        List<Object> rawTableRefs =
                (List<Object>) map.getOrDefault("table_refs", Collections.emptyList());
        if (rawTableRefs == null || rawTableRefs.isEmpty()) {
            tableRefs = Collections.emptyList();
        } else {
            tableRefs = new ArrayList<>(rawTableRefs.size());
            for (Object ref : rawTableRefs) {
                tableRefs.add(ref != null ? ref.toString() : null);
            }
            tableRefs = Collections.unmodifiableList(tableRefs);
        }

        List<SubValue> subValues;
        List<Map<String, Object>> rawSubValues =
                (List<Map<String, Object>>) map.getOrDefault("sub_values", Collections.emptyList());
        if (rawSubValues == null || rawSubValues.isEmpty()) {
            subValues = Collections.emptyList();
        } else {
            subValues = new ArrayList<>(rawSubValues.size());
            for (Map<String, Object> raw : rawSubValues) {
                subValues.add(SubValue.fromMap(raw));
            }
            subValues = Collections.unmodifiableList(subValues);
        }

        return new RegisterValue(reg, operator, value, description,
                tableRefs, subValues);
    }

    public String getReg() {
        return reg;
    }

    public String getOperator() {
        return operator;
    }

    public String getValue() {
        return value;
    }

    public String getDescription() {
        return description;
    }

    public List<String> getTableRefs() {
        return tableRefs;
    }

    public List<SubValue> getSubValues() {
        return subValues;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("RegisterValue{");
        sb.append("reg='").append(reg).append('\'');
        if (operator != null) {
            sb.append(", operator='").append(operator).append('\'');
        }
        if (value != null) {
            sb.append(", value='").append(value).append('\'');
        }
        if (description != null) {
            sb.append(", description='").append(description).append('\'');
        }
        if (!tableRefs.isEmpty()) {
            sb.append(", tableRefs=").append(tableRefs);
        }
        if (!subValues.isEmpty()) {
            sb.append(", subValues=").append(subValues);
        }
        sb.append('}');
        return sb.toString();
    }
}
