/**
 * A jail's color, by its place among every jail named, alphabetically: the same jail is the
 * same color on every chart and every range, and a jail added later moves only those after it.
 *
 * Eight, checked as one list by the dataviz validator in both modes. A ninth jail and on are
 * not given a ninth color: they are drawn together, in grey, as "Other".
 */
export const slots = 8;

export const other = "var(--color-faint)";

export function jailColors(names: Iterable<string>): Map<string, string> {
  const sorted = [...new Set(names)].toSorted();
  return new Map(
    sorted.map((name, i) => [
      name,
      i < slots ? `var(--color-jail-${i + 1})` : other,
    ]),
  );
}
