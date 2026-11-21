/**
 * The name, F2B in capitals at 24px, and what it is beside it in two short lines at 10px, the
 * same size wherever it is shown.
 *
 * The two lines stand exactly as tall as the capitals: the last sits on their baseline (aligned
 * by last baseline), and the line height, 0.97, lifts the first one's ascenders to their tops.
 * Measured in the system font: capitals 17.2px tall at 24px, ascenders 7.6px at 10px, so
 * 17.2 - 7.6 is 9.7px between the two baselines.
 */
export function Wordmark() {
  return (
    <span className="inline-flex items-baseline-last gap-1.5 align-middle">
      <span className="text-2xl leading-none font-bold">F2B</span>
      <span className="flex flex-col text-[10px] leading-[0.97] font-medium text-muted">
        <span>fail2ban</span>
        <span>dashboard</span>
      </span>
    </span>
  );
}
