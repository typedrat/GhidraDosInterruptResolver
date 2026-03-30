package ghidradosinterruptresolver.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * A sub-value within a register specification. Sub-values represent
 * bit-fields or enumerated meanings of a register value and can be
 * nested recursively.
 */
public final class SubValue {

    private final String value;
    private final String description;
    private final List<SubValue> subValues;

    private SubValue(String value, String description, List<SubValue> subValues) {
        this.value = value;
        this.description = description;
        this.subValues = subValues;
    }

    @SuppressWarnings("unchecked")
    public static SubValue fromMap(Map<String, Object> map) {
        if (map == null) {
            return new SubValue(null, null, Collections.emptyList());
        }

        // Use toString() to safely handle SnakeYAML parsing numerics as Integer
        Object rawValue = map.get("value");
        String value = rawValue != null ? rawValue.toString() : null;

        Object rawDescription = map.get("description");
        String description = rawDescription != null ? rawDescription.toString() : null;

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

        return new SubValue(value, description, subValues);
    }

    public String getValue() {
        return value;
    }

    public String getDescription() {
        return description;
    }

    public List<SubValue> getSubValues() {
        return subValues;
    }

    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder("SubValue{");
        if (value != null) {
            sb.append("value='").append(value).append('\'');
        }
        if (description != null) {
            sb.append(", description='").append(description).append('\'');
        }
        if (!subValues.isEmpty()) {
            sb.append(", subValues=").append(subValues);
        }
        sb.append('}');
        return sb.toString();
    }
}
