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
        List<Level> levels = lookupLevels(interruptNumber, ahValue, alValue);
        return levels.isEmpty() ? Collections.emptyList() : levels.get(0).entries();
    }

    /** Which selector a set of candidate entries was matched on. */
    public enum LevelKind { AX, AH, NONE }

    /** Candidate entries matched on one selector. */
    public record Level(LevelKind kind, List<InterruptEntry> entries) {
    }

    /**
     * Returns every non-empty candidate list in resolution order (AX, AH,
     * no-function), so a caller can fall back to a less specific level when
     * none of a level's entries fit the call site.
     *
     * @param interruptNumber the interrupt vector (0x00-0xFF)
     * @param ahValue         the value of the AH register, or {@code null} if unknown
     * @param alValue         the value of the AL register, or {@code null} if unknown
     * @return the candidate lists, most specific first; possibly empty
     */
    public List<Level> lookupLevels(int interruptNumber, Long ahValue, Long alValue) {
        Map<String, List<InterruptEntry>> index = getIndex(interruptNumber);
        if (index == null || index.isEmpty()) {
            return Collections.emptyList();
        }

        List<Level> levels = new ArrayList<>(3);
        if (ahValue != null && alValue != null) {
            String axKey = String.format(Locale.ROOT, "%02X%02X", ahValue & 0xFF, alValue & 0xFF);
            addLevel(levels, LevelKind.AX, index.get(axKey));
        }
        if (ahValue != null) {
            String ahKey = String.format(Locale.ROOT, "%02X", ahValue & 0xFF);
            addLevel(levels, LevelKind.AH, index.get(ahKey));
        }
        addLevel(levels, LevelKind.NONE, index.get(NO_FUNCTION_KEY));
        return levels;
    }

    private static void addLevel(List<Level> levels, LevelKind kind,
                                 List<InterruptEntry> entries) {
        if (entries != null && !entries.isEmpty()) {
            levels.add(new Level(kind, entries));
        }
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

        return buildIndex(intFile, fileName, interruptNumber);
    }

    /**
     * Builds the function-code-to-entries index from a parsed interrupt file.
     */
    private Map<String, List<InterruptEntry>> buildIndex(InterruptFile intFile,
                                                          String fileName,
                                                          int interruptNumber) {
        List<InterruptEntry> entries = intFile.getEntries();
        if (entries == null || entries.isEmpty()) {
            return EMPTY_INDEX;
        }

        Map<String, List<InterruptEntry>> index = new HashMap<>();
        boolean hasKeyedEntries = entries.stream()
                .anyMatch(e -> e.getFunction() != null && !e.getFunction().isEmpty());

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

            if (key.isEmpty() && hasKeyedEntries && !isVectorWideService(entry, interruptNumber)) {
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
     * Whether an entry without a function code can stand for any call on a
     * vector that also has function-coded entries. Such entries are the
     * fallback when AH is unknown or unmatched, so only core DOS ({@code D})
     * and BIOS ({@code B}) services qualify, e.g. INT 12h GET MEMORY SIZE.
     * The rest are hardware IRQs, CPU exceptions or vendor hooks, which would
     * label every unresolved INT 10h as a coprocessor error or a third-party
     * video hook. CPU exceptions ({@code C}) are kept on vectors 1, 3 and 4,
     * which INT1, INT3 and INTO raise from code.
     */
    private static boolean isVectorWideService(InterruptEntry entry, int interruptNumber) {
        String category = entry.getCategory();
        if (category == null) {
            return false;
        }
        return switch (category) {
            case "D", "B" -> true;
            case "C" -> interruptNumber == 0x01 || interruptNumber == 0x03
                    || interruptNumber == 0x04;
            default -> false;
        };
    }

    /**
     * Normalizes a YAML function field value into an uppercase index key.
     *
     * <p>RBIL qualifies many functions with further selectors after the
     * AH/AX value, so those entries are indexed under the AH/AX part and
     * told apart at lookup time by their pinned input registers.
     *
     * <ul>
     *   <li>{@code null} or empty &rarr; {@code ""} (no-function key)</li>
     *   <li>{@code "4C"} &rarr; {@code "4C"} (AH-level, 2 hex digits)</li>
     *   <li>{@code "010F"} &rarr; {@code "010F"} (AX-level, 4 hex digits)</li>
     *   <li>{@code "4F06BL02"} &rarr; {@code "4F06"}, {@code "61BP6467"} &rarr; {@code "61"},
     *       {@code "E0SF06"} &rarr; {@code "E0"}</li>
     *   <li>{@code "BL00"}, {@code "DI0100"}, {@code "VX0001"} &rarr; {@code ""}</li>
     * </ul>
     *
     * @param function the raw function string from the YAML entry
     * @return the normalized uppercase key
     */
    static String normalizeFunctionKey(String function) {
        if (function == null || function.isEmpty()) {
            return NO_FUNCTION_KEY;
        }
        String upper = function.toUpperCase(Locale.ROOT);
        int hexRun = 0;
        while (hexRun < upper.length() && Character.digit(upper.charAt(hexRun), 16) >= 0) {
            hexRun++;
        }
        if (hexRun == upper.length()) {
            return upper;
        }
        // The qualifier's register name may itself start with a hex letter
        // (BX, CL, DI), so an odd run has borrowed that letter.
        return upper.substring(0, Math.min(hexRun - hexRun % 2, 4));
    }
}
