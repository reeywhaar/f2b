import { useLayoutEffect, useMemo, useRef, useState } from "react";

import type { Stats } from "@app/api/types";
import { other } from "@app/charts/colors";
import { count, day } from "@app/format";

const height = 200;
const pad = { top: 8, right: 8, bottom: 24, left: 36 };

type Series = { name: string; color: string };

/**
 * Bans per day, a bar a day, stacked by jail.
 *
 * A legend over it, a readout of the day under the pointer, and the same numbers as a table one
 * press away: some jail colors are under 3:1 against the card, so color is never the only way to
 * tell what a segment is.
 */
export function BansChart({
  stats,
  colors,
}: {
  stats: Stats;
  colors: Map<string, string>;
}) {
  const [table, setTable] = useState(false);
  const series = useMemo(() => seriesOf(stats, colors), [stats, colors]);
  const totals = useMemo(() => {
    const t = new Map<string, number>();
    for (const d of stats.perDay) {
      for (const [jail, n] of Object.entries(d.byJail)) {
        const name = colors.get(jail) === other ? "Other" : jail;
        t.set(name, (t.get(name) ?? 0) + n);
      }
    }
    return t;
  }, [stats, colors]);

  return (
    <div className="flex flex-col gap-3">
      <div className="flex flex-wrap items-center gap-x-4 gap-y-1">
        {series.length > 1 ? (
          <ul
            className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-muted"
            aria-label="Jails"
          >
            {series.map((s) => (
              <li key={s.name} className="flex items-center gap-1.5">
                <span
                  aria-hidden="true"
                  className="size-2.5 rounded-sm"
                  style={{ background: s.color }}
                />
                {s.name}
                <span className="text-faint tabular-nums">
                  {count(totals.get(s.name) ?? 0)}
                </span>
              </li>
            ))}
          </ul>
        ) : null}
        <span className="flex-1" />
        <button
          type="button"
          className="text-xs text-muted underline-offset-2 hover:text-fg hover:underline"
          onClick={() => setTable(!table)}
          aria-pressed={table}
        >
          {table ? "Show the chart" : "Show as a table"}
        </button>
      </div>
      {table ? (
        <DayTable stats={stats} series={series} colors={colors} />
      ) : (
        <Bars stats={stats} series={series} colors={colors} />
      )}
    </div>
  );
}

function seriesOf(stats: Stats, colors: Map<string, string>): Series[] {
  const named = stats.jails
    .filter((j) => colors.get(j) !== other)
    .toSorted()
    .map((name) => ({ name, color: colors.get(name)! }));
  if (stats.jails.some((j) => colors.get(j) === other)) {
    named.push({ name: "Other", color: other });
  }
  return named;
}

/** A day's counts by series, Other summed. */
function byseries(
  d: Stats["perDay"][number],
  colors: Map<string, string>,
): Map<string, number> {
  const m = new Map<string, number>();
  for (const [jail, n] of Object.entries(d.byJail)) {
    const name =
      colors.get(jail) === other || !colors.has(jail) ? "Other" : jail;
    m.set(name, (m.get(name) ?? 0) + n);
  }
  return m;
}

/** A round number at or above max, and the ticks to it. */
function scale(max: number): number[] {
  if (max <= 0) return [0, 1];
  const raw = max / 3;
  const pow = 10 ** Math.floor(Math.log10(raw));
  const step = [1, 2, 5, 10].map((m) => m * pow).find((s) => s >= raw)!;
  const ticks: number[] = [];
  for (let v = 0; v < max + step; v += step) ticks.push(v);
  return ticks;
}

function Bars({
  stats,
  series,
  colors,
}: {
  stats: Stats;
  series: Series[];
  colors: Map<string, string>;
}) {
  const box = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [hover, setHover] = useState<number | null>(null);

  useLayoutEffect(() => {
    const el = box.current;
    if (!el) return;
    const measure = () => setWidth(Math.max(240, el.clientWidth));
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const days = stats.perDay;
  const ticks = scale(Math.max(0, ...days.map((d) => d.total)));
  const top = ticks[ticks.length - 1]!;
  const plotW = width - pad.left - pad.right;
  const plotH = height - pad.top - pad.bottom;
  const band = plotW / days.length;
  const barW = Math.max(2, Math.min(24, band * 0.72));
  const y = (v: number) => pad.top + plotH - (v / top) * plotH;
  const labelEvery = Math.ceil(
    days.length / Math.max(2, Math.floor(plotW / 64)),
  );
  const shown = hover === null ? null : days[hover];

  return (
    <div ref={box} className="relative">
      <svg
        width={width}
        height={height}
        role="img"
        aria-label={`Bans per day over ${days.length} days, ${count(stats.bans)} in all`}
        onPointerLeave={() => setHover(null)}
        className="block touch-pan-y"
      >
        {ticks.map((t) => (
          <g key={t}>
            <line
              x1={pad.left}
              x2={width - pad.right}
              y1={y(t)}
              y2={y(t)}
              stroke={t === 0 ? "var(--color-axis)" : "var(--color-grid)"}
            />
            <text
              x={pad.left - 6}
              y={y(t)}
              dy="0.32em"
              textAnchor="end"
              className="fill-faint text-[10px] tabular-nums"
            >
              {count(t)}
            </text>
          </g>
        ))}
        {days.map((d, i) => {
          const x = pad.left + i * band + (band - barW) / 2;
          const parts = byseries(d, colors);
          let base = 0;
          const segs = series
            .map((s) => ({ s, n: parts.get(s.name) ?? 0 }))
            .filter((p) => p.n > 0);
          const id = `bar-${i}`;
          return (
            <g key={d.day} opacity={hover === null || hover === i ? 1 : 0.45}>
              <clipPath id={id}>
                {/* Round at the top only: the clip runs on past the baseline. */}
                <rect
                  x={x}
                  y={y(d.total)}
                  width={barW}
                  height={y(0) - y(d.total) + 6}
                  rx={Math.min(4, barW / 2)}
                />
              </clipPath>
              <g clipPath={`url(#${id})`}>
                {segs.map(({ s, n }, k) => {
                  const y0 = y(base);
                  base += n;
                  const y1 = y(base);
                  // A 2px gap of the card between segments, taken from the upper one.
                  const gap = k > 0 && y0 - y1 > 3 ? 2 : 0;
                  return (
                    <rect
                      key={s.name}
                      x={x}
                      y={y1}
                      width={barW}
                      height={Math.max(0, y0 - y1 - gap)}
                      fill={s.color}
                    />
                  );
                })}
              </g>
              {(days.length - 1 - i) % labelEvery === 0 ? (
                <text
                  x={x + barW / 2}
                  y={height - 6}
                  textAnchor={i === days.length - 1 ? "end" : "middle"}
                  className="fill-faint text-[10px]"
                >
                  {day(d.day)}
                </text>
              ) : null}
              {/* The whole column answers the pointer, not only the bar. */}
              <rect
                x={pad.left + i * band}
                y={pad.top}
                width={band}
                height={plotH}
                fill="transparent"
                onPointerEnter={() => setHover(i)}
                onPointerDown={() => setHover(i)}
              />
            </g>
          );
        })}
      </svg>
      {shown ? (
        <Readout
          d={shown}
          series={series}
          colors={colors}
          left={pad.left + hover! * band + band / 2}
          width={width}
        />
      ) : null}
    </div>
  );
}

function Readout({
  d,
  series,
  colors,
  left,
  width,
}: {
  d: Stats["perDay"][number];
  series: Series[];
  colors: Map<string, string>;
  left: number;
  width: number;
}) {
  const parts = byseries(d, colors);
  const flip = left > width / 2;
  return (
    <div
      role="status"
      className="pointer-events-none absolute top-0 z-10 min-w-36 rounded-md border border-line bg-bg px-3 py-2 text-xs shadow-sm"
      style={flip ? { right: width - left + 12 } : { left: left + 12 }}
    >
      <p className="font-medium">
        {day(d.day)} · {count(d.total)} {d.total === 1 ? "ban" : "bans"}
      </p>
      <ul className="mt-1 flex flex-col gap-0.5 text-muted">
        {series
          .filter((s) => (parts.get(s.name) ?? 0) > 0)
          .toReversed()
          .map((s) => (
            <li key={s.name} className="flex items-center gap-1.5">
              <span
                aria-hidden="true"
                className="size-2 rounded-sm"
                style={{ background: s.color }}
              />
              <span className="flex-1">{s.name}</span>
              <span className="text-fg tabular-nums">
                {count(parts.get(s.name)!)}
              </span>
            </li>
          ))}
      </ul>
    </div>
  );
}

function DayTable({
  stats,
  series,
  colors,
}: {
  stats: Stats;
  series: Series[];
  colors: Map<string, string>;
}) {
  return (
    <div className="scroll-thin max-h-80 overflow-auto rounded-md border border-line">
      <table className="w-full text-left text-xs tabular-nums">
        <thead className="sticky top-0 bg-bg text-muted">
          <tr>
            <th className="px-3 py-1.5 font-medium">Day</th>
            {series.map((s) => (
              <th key={s.name} className="px-3 py-1.5 text-right font-medium">
                {s.name}
              </th>
            ))}
            <th className="px-3 py-1.5 text-right font-medium">All</th>
          </tr>
        </thead>
        <tbody>
          {stats.perDay.toReversed().map((d) => {
            const parts = byseries(d, colors);
            return (
              <tr key={d.day} className="border-t border-line">
                <td className="px-3 py-1">{day(d.day)}</td>
                {series.map((s) => (
                  <td key={s.name} className="px-3 py-1 text-right">
                    {parts.get(s.name) ?? 0}
                  </td>
                ))}
                <td className="px-3 py-1 text-right font-medium">{d.total}</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}
