import { languageMap } from "prism-code-editor";
import { languages } from "prism-code-editor/prism";

/**
 * fail2ban's INI, as one reads it: sections, keys, values that carry on over indented lines,
 * comments, and inside values the two things worth seeing at a glance — %(name)s, which is
 * another key's value, and <HOST>, <ADDR> and the rest, which are fail2ban's.
 *
 * Nothing here judges whether a file is right; fail2ban does that on Save.
 */
const insideValue = {
  interpolation: { pattern: /%\([^)\n]+\)s/, alias: "variable" },
  tag: { pattern: /<\/?[A-Za-z][\w-]*>/, alias: "keyword" },
};

languages.fail2ban = {
  comment: /^[ \t]*[#;].*/m,
  section: {
    pattern: /^[ \t]*\[[^\n\]]*\]?/m,
    inside: {
      "section-name": { pattern: /[^[\]\s][^[\]\n]*/, alias: "selector" },
      punctuation: /[[\]]/,
    },
  },
  // At the start of a line only: an indented line is the value above carrying on, even with a
  // colon in it, as a regex's often has.
  key: { pattern: /^[^\s=:#;[][^=:\n]*?(?=[ \t]*[=:])/m, alias: "attr-name" },
  value: {
    pattern: /([=:][ \t]*)[^\n]*(?:\n[ \t]+[^\s#;][^\n]*)*/,
    lookbehind: true,
    alias: "attr-value",
    inside: insideValue,
  },
  punctuation: /[=:]/,
};

languageMap.fail2ban = { comments: { line: "#" } };
