import { useQuery } from "@tanstack/react-query";

import { getStockFile } from "@app/api/actions";
import { qk } from "@app/api/keys";
import { messageOf } from "@app/api/transport";
import { Button } from "@app/components/Button";
import { DummyRows } from "@app/components/Dummy";
import { Frame } from "@app/components/Frame";
import { CodeEditor } from "@app/editor/CodeEditor";
import { Crumbs } from "@app/islands/app/Crumbs";
import { go, paths } from "@app/islands/app/route";

/** One of fail2ban's own files, read-only, with the way to override it. */
export function Stock({ path }: { path: string }) {
  const file = useQuery({
    queryKey: qk.stockFile(path),
    queryFn: () => getStockFile(path),
  });
  const [dir, name] = path.includes("/") ? path.split("/", 2) : ["", path];
  const kind =
    dir === "filter.d" ? "filters" : dir === "action.d" ? "actions" : null;
  const local = name!.replace(/\.conf$/, ".local");

  return (
    <Frame>
      <div className="flex flex-col gap-3">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-2">
          <Crumbs
            section={
              kind === "filters"
                ? "Filters"
                : kind === "actions"
                  ? "Actions"
                  : undefined
            }
            name={name!}
          />
          <span className="rounded bg-fill px-1.5 py-0.5 text-xs text-muted">
            fail2ban&rsquo;s own, read-only
          </span>
          <span className="flex-1" />
          {kind ? (
            <Button
              variant="solid"
              onClick={() => go(paths.file(kind, local, true))}
            >
              Override…
            </Button>
          ) : null}
        </div>
        {kind ? (
          <p className="max-w-3xl text-sm text-muted">
            Override makes{" "}
            <code className="font-mono text-xs">
              {dir}/{local}
            </code>
            , which fail2ban reads after this one: what it sets wins, and the
            rest stays as it is here.
          </p>
        ) : null}
        {file.isError ? (
          <p className="text-sm text-accent">{messageOf(file.error)}</p>
        ) : file.data ? (
          <CodeEditor
            label={`${path}, read-only`}
            value={file.data.content}
            readOnly
          />
        ) : (
          <DummyRows count={8} />
        )}
      </div>
    </Frame>
  );
}
