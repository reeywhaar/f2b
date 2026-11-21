import type { ReactNode } from "react";

import { messageOf } from "@app/api/transport";
import { Boundary } from "@app/components/Boundary";
import { Button } from "@app/components/Button";
import { DummyLines } from "@app/components/Dummy";
import { Heading } from "@app/components/Heading";

/**
 * A section of a settings page: its name, then what is set, or a shape where it will be while
 * it is read, or a sentence and a retry when it could not be.
 *
 * Changing what is set is never done in place: a section offers a button that opens a dialog,
 * and nothing applies until that dialog's Save.
 */
export function Panel({
  title,
  state,
  dummy,
  children,
}: {
  title: string;
  /** The query this section is waiting on, if it waits on one. */
  state?: {
    isPending: boolean;
    isError: boolean;
    error?: unknown;
    refetch: () => void;
  };
  dummy?: ReactNode;
  children: ReactNode;
}) {
  return (
    <section>
      <Heading>{title}</Heading>
      <Boundary what={title} onReset={() => state?.refetch()}>
        {state?.isError ? (
          <div className="flex flex-wrap items-center gap-3">
            <p className="text-sm text-accent">
              {title} could not be read. {messageOf(state.error)}
            </p>
            <Button onClick={() => state.refetch()}>Try again</Button>
          </div>
        ) : state?.isPending ? (
          (dummy ?? <DummyLines />)
        ) : (
          children
        )}
      </Boundary>
    </section>
  );
}
