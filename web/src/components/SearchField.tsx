import { useRef, type InputHTMLAttributes } from "react";

import { CrossIcon } from "@app/components/icons/Icon";
import { fieldHeight, fieldLook } from "@app/components/TextField";

/**
 * A field that narrows what is shown, as it is typed, with a cross to empty it. The cross is the
 * application's own rather than the browser's, which only some browsers draw.
 */
export function SearchField({
  value,
  onChange,
  className = "",
  inputClassName = "",
  ...props
}: Omit<InputHTMLAttributes<HTMLInputElement>, "value" | "onChange"> & {
  value: string;
  onChange: (value: string) => void;
  inputClassName?: string;
}) {
  const input = useRef<HTMLInputElement>(null);
  return (
    <span className={`relative inline-flex items-center ${className}`}>
      <input
        ref={input}
        type="search"
        autoComplete="off"
        spellCheck={false}
        className={`${fieldLook} ${fieldHeight} w-full min-w-0 pr-9 ${inputClassName}`}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        {...props}
      />
      {value ? (
        <button
          type="button"
          aria-label="Clear"
          title="Clear"
          onClick={() => {
            onChange("");
            input.current?.focus();
          }}
          className="absolute right-1.5 flex rounded p-1 text-faint hover:bg-control-hover hover:text-fg"
        >
          <CrossIcon />
        </button>
      ) : null}
    </span>
  );
}
