import { useEffect, useState } from "react";

import { CheckIcon, CopyIcon } from "@app/components/icons/Icon";
import { Link } from "@app/islands/app/Link";

/**
 * An address, linked to its bans, with a button that copies it: an address is taken elsewhere
 * more often than it is read, and selecting one by hand is a press on its link.
 */
export function Address({
  ip,
  href,
  replace = false,
  className = "",
}: {
  ip: string;
  href: string;
  replace?: boolean;
  className?: string;
}) {
  const [copied, setCopied] = useState(false);
  useEffect(() => {
    if (!copied) return;
    const t = setTimeout(() => setCopied(false), 1500);
    return () => clearTimeout(t);
  }, [copied]);

  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <Link
        href={href}
        replace={replace}
        className={`font-mono hover:underline ${className}`}
      >
        {ip}
      </Link>
      {/* The clipboard is a browser's only over https and on localhost; elsewhere a button
          that cannot work is left out. */}
      {navigator.clipboard ? (
        <button
          type="button"
          aria-label={copied ? `Copied ${ip}` : `Copy ${ip}`}
          title={copied ? "Copied" : "Copy"}
          onClick={() =>
            navigator.clipboard.writeText(ip).then(
              () => setCopied(true),
              () => {},
            )
          }
          className="flex shrink-0 rounded p-0.5 text-faint hover:bg-control-hover hover:text-fg"
        >
          {copied ? <CheckIcon className="text-brand" /> : <CopyIcon />}
        </button>
      ) : null}
    </span>
  );
}
