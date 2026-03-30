package ghidradosinterruptresolver;

import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import org.yaml.snakeyaml.LoaderOptions;
import org.yaml.snakeyaml.Yaml;
import org.yaml.snakeyaml.constructor.SafeConstructor;

import generic.jar.ResourceFile;
import ghidra.framework.Application;
import ghidra.util.Msg;
import ghidradosinterruptresolver.model.InterruptEntry;
import ghidradosinterruptresolver.model.InterruptFile;

/**
 * Database of x86 real-mode interrupt definitions loaded from YAML files
 * in the extension's {@code data/rbil-yaml/interrupts/} directory. The YAML data
 * originates from Ralf Brown's Interrupt List.
 *
 * <p>Files are lazily loaded on first access for a given interrupt number
 * and cached for the lifetime of the Ghidra session. All public methods
 * are safe to call from multiple analyzer threads concurrently.
 */
public final class InterruptDatabase {

    private static final String INTERRUPTS_DIR = "rbil-yaml/interrupts";
    private static final String NO_FUNCTION_KEY = "";

    /**
     * Sentinel value stored in {@link #cache} to indicate that a file was
     * already attempted (and either loaded or found missing/unparseable)
     * so we don't retry on every lookup.
     */
    private static final Map<String, List<InterruptEntry>> EMPTY_INDEX =
            Collections.emptyMap();

    /** Singleton holder - thread-safe lazy initialization. */
    private static final class Holder {
        static final InterruptDatabase INSTANCE = new InterruptDatabase();
    }

    /**
     * Returns the singleton instance of the interrupt database.
     *
     * @return the shared {@code InterruptDatabase}
     */
    public static InterruptDatabase getInstance() {
        return Holder.INSTANCE;
    }

    /**
     * Clears all cached interrupt data, forcing a reload from YAML files
     * on the next lookup. This is provided for cases where the on-disk
     * YAML data has been modified while Ghidra is running. Under normal
     * operation, the cache is valid for the lifetime of the Ghidra session
     * because the bundled YAML files are immutable.
     */
    public void clearCache() {
        cache.clear();
    }

    /**
     * Cache of loaded interrupt files. Key is the interrupt number (0x00-0xFF).
     * Value is a map from normalized function code to matching entries.
     * A value of {@link #EMPTY_INDEX} means the file was already attempted
     * but contained no usable entries (or did not exist).
     */
    private final ConcurrentHashMap<Integer, Map<String, List<InterruptEntry>>> cache =
            new ConcurrentHashMap<>();

    private InterruptDatabase() {
        // singleton
    }

    /**
     * Look up interrupt entries matching the given interrupt number and
     * optional register values.
     *
     * <p>Resolution order (most specific first):
     * <ol>
     *   <li>AX match (4-digit hex) if both {@code ahValue} and {@code alValue}
     *       are provided</li>
     *   <li>AH match (2-digit hex) if {@code ahValue} is provided</li>
     *   <li>No-function entries (entries with no function selector)</li>
     * </ol>
     *
     * @param interruptNumber the interrupt vector (0x00-0xFF)
     * @param ahValue         the value of the AH register, or {@code null} if unknown
     * @param alValue         the value of the AL register, or {@code null} if unknown
     * @return an unmodifiable list of matching entries, possibly empty
     */
    public List<InterruptEntry> lookup(int interruptNumber, Long ahValue, Long alValue) {
        Map<String, List<InterruptEntry>> index = getIndex(interruptNumber);
        if (index == null || index.isEmpty()) {
            return Collections.emptyList();
        }

        // Try AX-level match first (4-digit hex) when both halves are known
        if (ahValue != null && alValue != null) {
            String axKey = String.format(Locale.ROOT, "%02X%02X", ahValue & 0xFF, alValue & 0xFF);
            List<InterruptEntry> result = index.get(axKey);
            if (result != null) {
                return result;
            }
        }

        // Try AH-level match (2-digit hex)
        if (ahValue != null) {
            String ahKey = String.format(Locale.ROOT, "%02X", ahValue & 0xFF);
            List<InterruptEntry> result = index.get(ahKey);
            if (result != null) {
                return result;
            }
        }

        // Fall back to no-function entries
        List<InterruptEntry> noFunc = index.get(NO_FUNCTION_KEY);
        return noFunc != null ? noFunc : Collections.emptyList();
    }

    /**
     * Returns the full index for a given interrupt number, loading from
     * YAML if this is the first access.
     */
    private Map<String, List<InterruptEntry>> getIndex(int interruptNumber) {
        return cache.computeIfAbsent(interruptNumber, this::loadInterruptFile);
    }

    /**
     * Loads and indexes the YAML file for a single interrupt number.
     *
     * @param interruptNumber the interrupt vector (0x00-0xFF)
     * @return the function-code-to-entries index, or {@link #EMPTY_INDEX}
     *         if the file is missing or unparseable
     */
    private Map<String, List<InterruptEntry>> loadInterruptFile(int interruptNumber) {
        String fileName = String.format("int_%02x.yaml", interruptNumber);
        String relativePath = INTERRUPTS_DIR + "/" + fileName;

        ResourceFile yamlFile;
        try {
            yamlFile = Application.getModuleDataFile(relativePath);
        } catch (Exception e) {
            // File not found — no definitions for this interrupt number
            return EMPTY_INDEX;
        }

        Msg.info(this, "Loading interrupt definitions from " + fileName);

        InterruptFile intFile;
        try (InputStream is = yamlFile.getInputStream()) {
            Yaml yaml = new Yaml(new SafeConstructor(new LoaderOptions()));
            Map<String, Object> data = yaml.load(is);
            if (data == null) {
                Msg.warn(this, "Empty YAML content in " + fileName);
                return EMPTY_INDEX;
            }
            intFile = InterruptFile.fromMap(data);
        } catch (IOException e) {
            Msg.warn(this, "I/O error reading " + fileName + ": " + e.getMessage());
            return EMPTY_INDEX;
        } catch (Exception e) {
            Msg.warn(this, "Failed to parse " + fileName + ": " + e.getMessage());
            return EMPTY_INDEX;
        }

        return buildIndex(intFile, fileName);
    }

    /**
     * Builds the function-code-to-entries index from a parsed interrupt file.
     */
    private Map<String, List<InterruptEntry>> buildIndex(InterruptFile intFile,
                                                          String fileName) {
        List<InterruptEntry> entries = intFile.getEntries();
        if (entries == null || entries.isEmpty()) {
            return EMPTY_INDEX;
        }

        Map<String, List<InterruptEntry>> index = new HashMap<>();

        for (InterruptEntry entry : entries) {
            String key;
            try {
                key = normalizeFunctionKey(entry.getFunction());
            } catch (Exception e) {
                Msg.warn(this, "Skipping entry " + entry.getId()
                        + " in " + fileName + ": bad function value '"
                        + entry.getFunction() + "'");
                continue;
            }

            index.computeIfAbsent(key, k -> new ArrayList<>()).add(entry);
        }

        // Make each entry list unmodifiable
        Map<String, List<InterruptEntry>> result = new HashMap<>(index.size());
        for (Map.Entry<String, List<InterruptEntry>> e : index.entrySet()) {
            result.put(e.getKey(), Collections.unmodifiableList(e.getValue()));
        }

        return Collections.unmodifiableMap(result);
    }

    /**
     * Normalizes a YAML function field value into an uppercase index key.
     *
     * <ul>
     *   <li>{@code null} or empty &rarr; {@code ""} (no-function key)</li>
     *   <li>{@code "4C"} &rarr; {@code "4C"} (AH-level, 2 hex digits)</li>
     *   <li>{@code "010F"} &rarr; {@code "010F"} (AX-level, 4 hex digits)</li>
     *   <li>{@code "SI6A6A"} &rarr; {@code "SI6A6A"} (register-prefixed, stored as-is)</li>
     * </ul>
     *
     * @param function the raw function string from the YAML entry
     * @return the normalized uppercase key
     */
    private static String normalizeFunctionKey(String function) {
        if (function == null || function.isEmpty()) {
            return NO_FUNCTION_KEY;
        }
        return function.toUpperCase(Locale.ROOT);
    }
}
