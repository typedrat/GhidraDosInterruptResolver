package ghidradosinterruptresolver;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Objects;
import java.util.Set;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import ghidradosinterruptresolver.InterruptDatabase.Level;
import ghidradosinterruptresolver.InterruptDatabase.LevelKind;
import ghidradosinterruptresolver.model.EntryFlag;
import ghidradosinterruptresolver.model.InterruptEntry;
import ghidradosinterruptresolver.model.RegisterValue;

/**
 * Chooses among interrupt entries that share a selector by checking the
 * other registers each entry pins to a constant (e.g. {@code BX = 4D41h}
 * for a TSR installation check) against values resolved at the call site.
 *
 * <p>A selector alone only identifies the group's standard service: the
 * first entry, in RBIL order, from a trusted category that is neither
 * protected-mode only nor a hooked callout. RBIL lists the standard service
 * first, and the rest of a group is mostly vendor extensions and TSR
 * install checks that reuse the same AH/AX. Any other entry is chosen only
 * when the call site confirms one of its pins outside AX, so an unconfirmed
 * vendor call is left unresolved rather than mislabelled.
 */
public class EntrySelector {

    private static final Set<String> ACCUMULATOR = Set.of("AX", "AH", "AL");

    private final RegisterResolver resolver;
    private final Set<String> trustedCategories;

    /**
     * @param trustedCategories RBIL category letters (case-sensitive) whose
     *        entries may be chosen on their selector alone
     */
    public EntrySelector(RegisterResolver resolver, Set<String> trustedCategories) {
        this.resolver = resolver;
        this.trustedCategories = trustedCategories;
    }

    /**
     * The outcome of a selection: the chosen entry, if any, and every
     * candidate the call site did not rule out, most specific level first.
     */
    public record Selection(InterruptEntry entry, List<InterruptEntry> candidates) {
    }

    /**
     * Picks the best entry from the first level that has one consistent with
     * the call site. Within a level, an entry is rejected if a resolved
     * register contradicts one of its pins or if it is neither the group's
     * standard service nor backed by a confirmed qualifier pin; the rest are
     * ranked by confirmed pins, then by fewest unconfirmed pins, then by RBIL
     * order.
     *
     * <p>An AX-level match does not displace an AH-level entry that takes AL
     * as an argument when the two come from different RBIL categories, unless
     * the call site confirms one of the AX entry's other pins. Otherwise
     * DOS-extender entries such as FlashTek's AX=3504h take over plain
     * {@code GET INTERRUPT VECTOR} for INT 04h.
     *
     * @return the chosen entry, which is {@code null} if no candidate is
     *         both consistent with the call site and trusted
     */
    public Selection select(Program program, Address intAddr,
                            List<Level> levels, TaskMonitor monitor) {
        // Resolved values are shared across candidates; a null value means
        // the register was tried and could not be determined.
        Map<String, Long> resolved = new HashMap<>();
        List<InterruptEntry> consistent = new ArrayList<>();

        for (int i = 0; i < levels.size(); i++) {
            Level level = levels.get(i);
            Ranked best = bestInLevel(program, intAddr, level.entries(), resolved,
                    consistent, monitor);
            if (best == null) {
                continue;
            }
            if (level.kind() == LevelKind.AX && best.confirmedQualifiers() == 0
                    && i + 1 < levels.size() && levels.get(i + 1).kind() == LevelKind.AH) {
                Ranked ahBest = bestInLevel(program, intAddr, levels.get(i + 1).entries(),
                        resolved, null, monitor);
                if (ahBest != null && takesAlArgument(ahBest.entry())
                        && !Objects.equals(best.entry().getCategory(),
                                ahBest.entry().getCategory())) {
                    return new Selection(ahBest.entry(), List.of());
                }
            }
            return new Selection(best.entry(), List.of());
        }

        return new Selection(null, consistent);
    }

    /**
     * An entry with its pin score. {@code confirmedQualifiers} counts
     * confirmed pins on registers other than AX, AH and AL.
     */
    private record Ranked(InterruptEntry entry, int confirmed, int unconfirmed,
                          int confirmedQualifiers) {
    }

    /**
     * Ranks one level's candidates.
     *
     * @param consistent if non-null, receives every candidate whose pins do
     *        not conflict with the call site, trusted or not
     */
    private Ranked bestInLevel(Program program, Address intAddr,
                               List<InterruptEntry> candidates, Map<String, Long> resolved,
                               List<InterruptEntry> consistent, TaskMonitor monitor) {
        Ranked best = null;
        InterruptEntry standard = candidates.stream()
                .filter(this::isStandardService)
                .findFirst()
                .orElse(null);

        for (InterruptEntry entry : candidates) {
            int confirmed = 0;
            int unconfirmed = 0;
            int confirmedQualifiers = 0;
            boolean conflict = false;

            for (Map.Entry<String, Set<Long>> pin : getPins(entry).entrySet()) {
                String regName = pin.getKey();
                if (!resolved.containsKey(regName)) {
                    resolved.put(regName, resolve(program, intAddr, regName, monitor));
                }
                Long actual = resolved.get(regName);
                if (actual == null) {
                    unconfirmed++;
                } else if (pin.getValue().contains(actual)) {
                    confirmed++;
                    if (!ACCUMULATOR.contains(regName)) {
                        confirmedQualifiers++;
                    }
                } else {
                    conflict = true;
                    break;
                }
            }

            if (conflict) {
                continue;
            }
            if (consistent != null) {
                consistent.add(entry);
            }
            if (entry != standard && confirmedQualifiers == 0) {
                continue;
            }
            if (best == null || confirmed > best.confirmed()
                    || (confirmed == best.confirmed() && unconfirmed < best.unconfirmed())) {
                best = new Ranked(entry, confirmed, unconfirmed, confirmedQualifiers);
            }
        }

        return best;
    }

    /**
     * Whether an entry can be a selector's standard service. Callouts are
     * hooked by the system rather than invoked, except CPU exceptions,
     * which INT1, INT3 and INTO raise from code.
     */
    private boolean isStandardService(InterruptEntry entry) {
        String category = entry.getCategory();
        if (category == null || !trustedCategories.contains(category)) {
            return false;
        }
        List<EntryFlag> flags = entry.getFlags();
        if (flags.contains(EntryFlag.PROTECTED_MODE)) {
            return false;
        }
        return !flags.contains(EntryFlag.CALLBACK) || "C".equals(category);
    }

    /** Whether the entry reads AL as an argument rather than a selector. */
    private static boolean takesAlArgument(InterruptEntry entry) {
        for (RegisterValue rv : entry.getInputRegisters()) {
            if ("AL".equalsIgnoreCase(rv.getReg()) && parseHexValue(rv.getValue()) == null) {
                return true;
            }
        }
        return false;
    }

    private Long resolve(Program program, Address intAddr, String regName,
                         TaskMonitor monitor) {
        Register reg = program.getRegister(regName);
        if (reg == null) {
            return null;
        }
        return resolver.resolveRegister(program, intAddr, reg, monitor);
    }

    /**
     * Collects the input registers an entry pins to constants, keyed by
     * register name. RBIL sometimes lists one register more than once
     * (alternative signatures), so each maps to every allowed value.
     */
    static Map<String, Set<Long>> getPins(InterruptEntry entry) {
        Map<String, Set<Long>> pins = new LinkedHashMap<>();
        for (RegisterValue rv : entry.getInputRegisters()) {
            String reg = rv.getReg();
            if (reg == null || reg.contains(":") || !"=".equals(rv.getOperator())) {
                continue;
            }
            Long value = parseHexValue(rv.getValue());
            if (value == null) {
                continue;
            }
            pins.computeIfAbsent(reg.toUpperCase(Locale.ROOT), k -> new HashSet<>()).add(value);
        }
        return pins;
    }

    /**
     * Parses an RBIL constant such as {@code 4Bh} or {@code 00B6h}; returns
     * {@code null} for anything else (descriptions, ranges, strings).
     */
    static Long parseHexValue(String value) {
        if (value == null) {
            return null;
        }
        String v = value.trim();
        if (v.length() < 2 || Character.toLowerCase(v.charAt(v.length() - 1)) != 'h') {
            return null;
        }
        try {
            return Long.parseLong(v.substring(0, v.length() - 1), 16);
        } catch (NumberFormatException e) {
            return null;
        }
    }
}
