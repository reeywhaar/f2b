import { useEffect, useState } from "react";

import { CheckIcon, CopyIcon } from "@app/components/icons/Icon";

/**
 * Copies text, and says so for a moment. Left out where the browser has no clipboard, which it
 * has only over https and on localhost: a button that cannot work is worse than none.
 */
export function CopyButton({
  text,
  label,
  className = "",
}: {
  text: string;
  /** What is copied, as a screen reader says it: "Copy {label}". */
  label: string;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  if (!navigator.clipboard) return null;
  return (
    <button
      type="button"
      aria-label={copied ? `Copied ${label}` : `Copy ${label}`}
      title={copied ? "Copied" : "Copy"}
      onClick={() =>
        navigator.clipboard.writeText(text).then(
          () => setCopied(true),
          () => {},
        )
      }
      className={`flex shrink-0 rounded p-0.5 text-faint hover:bg-control-hover hover:text-fg ${className}`}
    >
      {copied ? <CheckIcon className="text-brand" /> : <CopyIcon />}
    </button>
  );
}
