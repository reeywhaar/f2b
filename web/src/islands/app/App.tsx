import { Boundary } from "@app/components/Boundary";
import { Bans } from "@app/islands/app/Bans";
import { Config } from "@app/islands/app/Config";
import { FileEditor } from "@app/islands/app/FileEditor";
import { Header } from "@app/islands/app/Header";
import { History } from "@app/islands/app/History";
import { Link } from "@app/islands/app/Link";
import { Log } from "@app/islands/app/Log";
import { Overview } from "@app/islands/app/Overview";
import { paths, useRoute, type Route } from "@app/islands/app/route";
import { Stock } from "@app/islands/app/Stock";

export function App() {
  const route = useRoute();
  return (
    <div className="flex min-h-dvh flex-col">
      <Header route={route} />
      <Boundary what="This page" key={route.page}>
        <Page route={route} />
      </Boundary>
    </div>
  );
}

function Page({ route }: { route: Route }) {
  switch (route.page) {
    case "overview":
      return <Overview days={route.days} />;
    case "bans":
      return <Bans />;
    case "history":
      return <History jail={route.jail} ip={route.ip} />;
    case "config":
      return <Config />;
    case "file":
      return (
        <FileEditor
          key={`${route.kind}/${route.name}`}
          kind={route.kind}
          name={route.name}
          fresh={route.fresh}
        />
      );
    case "stock":
      return <Stock key={route.path} path={route.path} />;
    case "log":
      return <Log />;
    case "missing":
      return (
        <main className="flex flex-1 flex-col items-center justify-center gap-3 p-4">
          <p className="text-sm text-muted">
            There is nothing at this address.
          </p>
          <Link href={paths.overview()} className="text-sm underline">
            Go to the overview
          </Link>
        </main>
      );
  }
}
