import { ChevronRightIcon } from "@app/components/icons/Icon";
import { Link } from "@app/islands/app/Link";
import { paths } from "@app/islands/app/route";

/**
 * Where a file is: Config, the section of it the file is listed under, and the file, which is the
 * page's title. The section is a name rather than a link: it is a part of the Config page, not a
 * page of its own.
 */
export function Crumbs({
  section,
  name,
}: {
  /** The heading on the Config page the file is under, if it is under one. */
  section?: string;
  name: string;
}) {
  const chevron = <ChevronRightIcon className="shrink-0 text-faint" />;
  return (
    <>
      <Link href={paths.config} className="text-sm text-muted hover:text-fg">
        Config
      </Link>
      {chevron}
      {section ? (
        <>
          <span className="text-sm text-muted">{section}</span>
          {chevron}
        </>
      ) : null}
      <h1 className="text-sm">{name}</h1>
    </>
  );
}
