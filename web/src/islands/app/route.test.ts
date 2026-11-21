import { parse, paths } from "@app/islands/app/route";

test("every path the app makes parses back to where it was made for", () => {
  expect(parse(paths.overview())).toEqual({ page: "overview", days: 30 });
  expect(parse(paths.overview(7))).toEqual({ page: "overview", days: 7 });
  expect(parse(paths.bans)).toEqual({ page: "bans" });
  expect(parse(paths.history({ jail: "sshd", ip: "2001:db8::1" }))).toEqual({
    page: "history",
    jail: "sshd",
    ip: "2001:db8::1",
  });
  expect(parse(paths.file("filters", "caddy-scanners.local"))).toEqual({
    page: "file",
    kind: "filters",
    name: "caddy-scanners.local",
    fresh: false,
  });
  expect(parse(paths.file("jails", "x.local", true))).toMatchObject({
    fresh: true,
  });
  expect(parse(paths.stock("filter.d/sshd.conf"))).toEqual({
    page: "stock",
    path: "filter.d/sshd.conf",
  });
});

test("a range nobody offers falls back to the default", () => {
  expect(parse("/?days=11")).toEqual({ page: "overview", days: 30 });
});

test("anything else is missing", () => {
  for (const p of [
    "/nope",
    "/config/widgets/x.local",
    "/bans/x",
    "/%E0%A4%A",
  ]) {
    expect(parse(p)).toEqual({ page: "missing" });
  }
});
