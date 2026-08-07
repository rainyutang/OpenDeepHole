import { StrictMode } from "react";
import { createRoot } from "react-dom/client";
import "./index.css";
import App from "./App";
import { ThemeProvider } from "./theme/ThemeProvider";
import RuntimeErrorBoundary from "./components/RuntimeErrorBoundary";

createRoot(document.getElementById("root")!).render(
  <StrictMode>
    <RuntimeErrorBoundary name="application-root" fullscreen>
      <ThemeProvider>
        <App />
      </ThemeProvider>
    </RuntimeErrorBoundary>
  </StrictMode>,
);
