import { useEffect, useRef } from "react";
import { createEditor, type PrismEditor } from "prism-code-editor";
import {
  defaultKeymap,
  editHistory,
  editorCommands,
} from "prism-code-editor/commands";
import { matchBrackets } from "prism-code-editor/match-brackets";
import {
  highlightSelectionMatches,
  searchWidget,
} from "prism-code-editor/search";
import "prism-code-editor/layout.css";
import "prism-code-editor/search.css";

import "@app/editor/fail2ban";

/**
 * prism-code-editor, for fail2ban's files: a textarea over highlighted text, so selection, IME
 * and the phone's keyboard are the browser's own.
 *
 * The editor is not controlled. It owns what is typed and reports it; a value from outside that
 * differs from what it holds — a file opened, a change discarded — replaces its content, which
 * is the one time its undo history is meant to go.
 */
export function CodeEditor({
  value,
  onChange,
  onSave,
  readOnly = false,
  label,
}: {
  value: string;
  onChange?: (value: string) => void;
  /** Cmd-S or Ctrl-S. */
  onSave?: () => void;
  readOnly?: boolean;
  label: string;
}) {
  const host = useRef<HTMLDivElement>(null);
  const editor = useRef<PrismEditor | null>(null);
  const handlers = useRef({ onChange, onSave });
  handlers.current = { onChange, onSave };

  useEffect(() => {
    const e = createEditor(
      host.current,
      {
        language: "fail2ban",
        value,
        readOnly,
        tabSize: 4,
        insertSpaces: true,
        lineNumbers: true,
        // Not while it is being made: that first update is the value it was given.
        onUpdate: (v) => {
          if (editor.current) handlers.current.onChange?.(v);
        },
      },
      editHistory(),
      editorCommands(defaultKeymap),
      searchWidget(),
      highlightSelectionMatches(),
      matchBrackets(),
    );
    e.textarea.setAttribute("aria-label", label);
    e.textarea.spellcheck = false;
    e.textarea.addEventListener("keydown", (ev) => {
      if ((ev.metaKey || ev.ctrlKey) && ev.key.toLowerCase() === "s") {
        ev.preventDefault();
        handlers.current.onSave?.();
      }
    });
    editor.current = e;
    return () => {
      editor.current = null;
      e.remove();
    };
    // Made once; value and readOnly from outside are followed below.
  }, []);

  useEffect(() => {
    const e = editor.current;
    if (e && e.value !== value) e.setOptions({ value });
  }, [value]);

  useEffect(() => {
    editor.current?.setOptions({ readOnly });
  }, [readOnly]);

  return (
    <div
      ref={host}
      className="f2b-editor grid overflow-hidden rounded-md border border-line"
    />
  );
}
