package ghidradosinterruptresolver.model;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;

/**
 * Top-level representation of a parsed YAML interrupt file from
 * Ralf Brown's Interrupt List. Each file covers one interrupt vector
 * and contains all known entries (functions/sub-functions) for it.
 */
public final class InterruptFile {

    private final String fileType;
    private final String key;
    private final List<InterruptEntry> entries;

    private InterruptFile(String fileType, String key,
                          List<InterruptEntry> entries) {
        this.fileType = fileType;
        this.key = key;
        this.entries = entries;
    }

    @SuppressWarnings("unchecked")
    public static InterruptFile fromMap(Map<String, Object> map) {
        if (map == null) {
            return new InterruptFile(null, null, Collections.emptyList());
        }

        String fileType = (String) map.get("file_type");

        Object rawKey = map.get("key");
        String key = rawKey != null ? rawKey.toString() : null;

        List<InterruptEntry> entries;
        List<Map<String, Object>> rawEntries =
                (List<Map<String, Object>>) map.getOrDefault("entries",
                        Collections.emptyList());
        if (rawEntries == null || rawEntries.isEmpty()) {
            entries = Collections.emptyList();
        } else {
            entries = new ArrayList<>(rawEntries.size());
            for (Map<String, Object> raw : rawEntries) {
                try {
                    entries.add(InterruptEntry.fromMap(raw));
                } catch (Exception e) {
                    // Skip malformed entry; others in this file remain usable
                }
            }
            entries = Collections.unmodifiableList(entries);
        }

        return new InterruptFile(fileType, key, entries);
    }

    public String getFileType() {
        return fileType;
    }

    public String getKey() {
        return key;
    }

    public List<InterruptEntry> getEntries() {
        return entries;
    }

    @Override
    public String toString() {
        return "InterruptFile{" +
                "fileType='" + fileType + '\'' +
                ", key='" + key + '\'' +
                ", entries=" + entries.size() +
                '}';
    }
}
