import type { JSX } from "react";
import { AppShell } from "./components/AppShell";
import { Dashboard } from "./screens/Dashboard";

// Root component. The app is intentionally simple/logic-light (TDD §6): all
// vulnerability behaviour lives server-side so the FYP analyses real surfaces.
export default function App(): JSX.Element {
  return (
    <AppShell>
      <Dashboard />
    </AppShell>
  );
}
