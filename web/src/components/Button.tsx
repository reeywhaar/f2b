import type { ComponentProps } from "react";

/**
 * Four variants, and choosing between them is the whole decision.
 *
 * solid is the brand color, which is the one thing on a screen of greys that is this
 * application rather than the browser's furniture, and so there is one of it in a view.
 */
export type Variant = "solid" | "quiet" | "link" | "danger";

/**
 * One height for every button, the fields' (fieldHeight), wherever it stands: on a page, in a
 * form, in a dialog, on a phone. Two heights had a page's controls and a dialog's disagree.
 */
const shape = "min-h-8 px-2.5 py-1 text-sm";

const styles: Record<Variant, string> = {
  solid: "bg-brand text-brand-ink hover:opacity-90",
  quiet: "bg-control text-fg hover:bg-control-hover",
  link: "text-muted underline-offset-2 hover:text-fg hover:underline",
  danger: "bg-control text-accent hover:bg-control-hover",
};

/** A button's look, for a link that moves somewhere to wear as well. */
export function buttonLook(variant: Variant = "quiet") {
  const box =
    variant === "link" ? "text-sm" : `${shape} justify-center rounded-md`;
  return `inline-flex items-center gap-1.5 disabled:opacity-50 ${box} ${styles[variant]}`;
}

/** A label ends in "…" when the command stops to ask, and not when it acts on the press. */
export function Button({
  variant = "quiet",
  className = "",
  ...props
}: ComponentProps<"button"> & {
  variant?: Variant;
}) {
  return (
    <button
      type="button"
      className={`${buttonLook(variant)} ${className}`}
      {...props}
    />
  );
}
