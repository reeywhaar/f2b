import { CopyButton } from "@app/components/CopyButton";
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
  return (
    <span className="inline-flex min-w-0 items-center gap-1">
      <Link
        href={href}
        replace={replace}
        className={`font-mono hover:underline ${className}`}
      >
        {ip}
      </Link>
      <CopyButton text={ip} label={ip} />
    </span>
  );
}
